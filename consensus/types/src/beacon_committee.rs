use crate::*;

type ValidatorIndex = usize;
type CommitteePosition = usize;

pub enum MaybeSortedCommittee<'a> {
    Sorted(&'a [(ValidatorIndex, CommitteePosition)]),
    Unsorted(&'a [ValidatorIndex]),
}

impl MaybeSortedCommittee<'_> {
    pub fn len(&self) -> usize {
        match self {
            MaybeSortedCommittee::Sorted(committee) => committee.len(),
            MaybeSortedCommittee::Unsorted(committee) => committee.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Default, Clone, Debug, PartialEq)]
pub struct BeaconCommittee<'a> {
    pub slot: Slot,
    pub index: CommitteeIndex,
    pub committee: &'a [usize],
}

impl BeaconCommittee<'_> {
    pub fn into_owned(self) -> OwnedBeaconCommittee {
        OwnedBeaconCommittee {
            slot: self.slot,
            index: self.index,
            committee: self.committee.to_vec(),
        }
    }

    pub fn unsorted_committee(&self) -> MaybeSortedCommittee {
        MaybeSortedCommittee::Unsorted(self.committee)
    }
}

#[derive(arbitrary::Arbitrary, Default, Clone, Debug, PartialEq)]
pub struct OwnedBeaconCommittee {
    pub slot: Slot,
    pub index: CommitteeIndex,
    pub committee: Vec<usize>,
}

impl OwnedBeaconCommittee {
    pub fn unsorted_committee(&self) -> MaybeSortedCommittee {
        MaybeSortedCommittee::Unsorted(&self.committee)
    }
}

#[derive(Default, Clone, Debug, PartialEq)]
pub struct SortedBeaconCommittee {
    pub slot: Slot,
    pub index: CommitteeIndex,
    /// Provides each validator index and its corresponding position in the
    /// shuffling for the committee. This list is sorted by
    /// increasing validator index.
    pub committee: Vec<(ValidatorIndex, CommitteePosition)>,
}

impl SortedBeaconCommittee {
    pub fn sorted_committee(&self) -> MaybeSortedCommittee {
        MaybeSortedCommittee::Sorted(&self.committee)
    }
}

impl From<BeaconCommittee<'_>> for SortedBeaconCommittee {
    fn from(unsorted: BeaconCommittee) -> Self {
        let BeaconCommittee {
            slot,
            index,
            committee,
        } = unsorted;

        let mut committee: Vec<_> = committee
            .iter()
            .enumerate()
            .map(|(committee_index, &validator_index)| (validator_index, committee_index))
            .collect();
        committee.sort_unstable_by_key(|(validator_index, _)| *validator_index);

        SortedBeaconCommittee {
            slot,
            index,
            committee,
        }
    }
}
