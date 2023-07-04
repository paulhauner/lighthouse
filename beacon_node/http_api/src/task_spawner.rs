use beacon_processor::{AsyncFn, BeaconProcessorSend, BlockingOrAsync, Work, WorkEvent};
use serde::Serialize;
use tokio::sync::{mpsc::error::TrySendError, oneshot};
use types::EthSpec;
use warp::reply::{Reply, Response};

#[derive(Clone, Copy)]
enum Priority {
    P0,
}

struct TaskSpawner<E: EthSpec> {
    beacon_processor_send: Option<BeaconProcessorSend<E>>,
}

impl<E: EthSpec> TaskSpawner<E> {
    pub fn new(beacon_processor_send: Option<BeaconProcessorSend<E>>) -> Self {
        Self {
            beacon_processor_send,
        }
    }

    pub async fn blocking_json_task<F, T>(
        &self,
        priority: Priority,
        func: F,
    ) -> Result<Response, warp::Rejection>
    where
        F: FnOnce() -> Result<T, warp::Rejection> + Send + Sync + 'static,
        T: Serialize + Send + 'static,
    {
        if let Some(beacon_processor_send) = &self.beacon_processor_send {
            // Create a closure that will execute `func` and send the result to
            // a channel held by this thread.
            let (tx, rx) = oneshot::channel();
            let process_fn = move || {
                // Execute the function, collect the return value.
                let func_result = func();
                // Send the result down the channel. Ignore any failures; the
                // send can only fail if the receiver is dropped.
                let _ = tx.send(func_result);
            };

            // Send the function to the beacon processor for execution at some arbitrary time.
            send_to_beacon_processor(
                beacon_processor_send,
                priority,
                BlockingOrAsync::Blocking(Box::new(process_fn)),
                rx,
            )
            .await
        } else {
            // There is no beacon processor, spawn a task directly on the tokio
            // executor.
            warp_utils::task::blocking_json_task(func).await
        }
    }
}

async fn send_to_beacon_processor<E: EthSpec, T>(
    beacon_processor_send: &BeaconProcessorSend<E>,
    priority: Priority,
    process_fn: BlockingOrAsync,
    rx: oneshot::Receiver<Result<T, warp::Rejection>>,
) -> Result<Response, warp::Rejection>
where
    T: Serialize + Send + 'static,
{
    let work = match priority {
        Priority::P0 => Work::ApiRequestP0(process_fn),
    };
    let work_event = WorkEvent {
        drop_during_sync: false,
        work,
    };

    let error_message = match beacon_processor_send.try_send(work_event) {
        Ok(()) => {
            match rx.await {
                // The beacon processor executed the task and sent a result.
                Ok(func_result) => {
                    return func_result.map(|r| warp::reply::json(&r).into_response())
                }
                // The beacon processor dropped the channel without sending a
                // result. The beacon processor dropped this task because its
                // queues are full or it's shutting down.
                Err(_) => "The task did not execute. Server is overloaded or shutting down.",
            }
        }
        Err(TrySendError::Full(_)) => "The node is overloaded and the task was dropped.",
        Err(TrySendError::Closed(_)) => "The node is shutting down and the task was dropped.",
    };

    let error_response = warp::reply::with_status(
        warp::reply::json(&error_message),
        eth2::StatusCode::INTERNAL_SERVER_ERROR,
    )
    .into_response();
    Ok(error_response)
}
