#![recursion_limit = "256"]
//! Provides procedural derive macros for the `Encode` and `Decode` traits of the `eth2_ssz` crate.
//!
//! ## Struct Attributes
//!
//! The following struct attributes are available:
//!
//! - `#[ssz(union)]`
//!     - For `enum`, implements `ssz::Encode` and `ssz::Decode` such that the union variant is
//!       encoded as a single byte in the SSZ vector.
//!     - Not supported for `struct`.
//! - `#[ssz(transparent)]`
//!     - For `enum`, implements `ssz::Encode` such that the `enum` is ignored. `ssz::Decode` is not
//!       supported.
//!     - For `struct`, implements `ssz::Encode` and `ssz::Decode` such that the outermost `struct`
//!       is ignored for encoding and decoding. This is useful for new-type wrappers. The `struct`
//!       must have exactly one non-skipped field.
//!
//! ## Field Attributes
//!
//! The following field attributes are available:
//!
//! - `#[ssz(with = "module")]`: uses the methods in `module` to implement `ssz::Encode` or
//!   `ssz::Decode`. This is useful when it's not possible to create an `impl` for that type
//!   (perhaps it is defined in another crate).
//! - `#[ssz(skip_serializing)]`: this field will not be included in the serialized SSZ vector.
//! - `#[ssz(skip_deserializing)]`: this field will not be expected to be included in the serialized
//!   SSZ vector and it will be initialized from a `Default` implementation.
//!
//! ## Examples
//!
//! ### Structs
//!
//! ```rust
//! use ssz::{Encode, Decode};
//! use ssz_derive::{Encode, Decode};
//!
//! /// Represented as an SSZ "list" wrapped in an SSZ "container".
//! #[derive(Debug, PartialEq, Encode, Decode)]
//! struct TypicalStruct {
//!     foo: Vec<u8>
//! }
//!
//! assert_eq!(
//!     TypicalStruct { foo: vec![42] }.as_ssz_bytes(),
//!     vec![4, 0, 0, 0, 42]
//! );
//!
//! assert_eq!(
//!     TypicalStruct::from_ssz_bytes(&[4, 0, 0, 0, 42]).unwrap(),
//!     TypicalStruct { foo: vec![42] },
//! );
//!
//! /// Represented as an SSZ "list" *without* an SSZ "container".
//! #[derive(Encode, Decode)]
//! #[ssz(transparent)]
//! struct NewType {
//!     foo: Vec<u8>
//! }
//!
//! assert_eq!(
//!     NewType { foo: vec![42] }.as_ssz_bytes(),
//!     vec![42]
//! );
//!
//! /// Represented as an SSZ "list" *without* an SSZ "container". The `bar` byte is ignored.
//! #[derive(Debug, PartialEq, Encode, Decode)]
//! #[ssz(transparent)]
//! struct NewTypeSkippedField {
//!     foo: Vec<u8>,
//!     #[ssz(skip_serializing, skip_deserializing)]
//!     bar: u8,
//! }
//!
//! assert_eq!(
//!     NewTypeSkippedField { foo: vec![42], bar: 99 }.as_ssz_bytes(),
//!     vec![42]
//! );
//! assert_eq!(
//!     NewTypeSkippedField::from_ssz_bytes(&[42]).unwrap(),
//!     NewTypeSkippedField { foo: vec![42], bar: 0 }
//! );
//! ```
//!
//! ### Enums
//!
//! ```rust
//! use ssz::{Encode, Decode};
//! use ssz_derive::{Encode, Decode};
//!
//! /// Represented as an SSZ "union".
//! #[derive(Debug, PartialEq, Encode, Decode)]
//! #[ssz(union)]
//! enum UnionEnum {
//!     Foo(u8),
//!     Bar(u8),
//! }
//!
//! assert_eq!(
//!     UnionEnum::Foo(42).as_ssz_bytes(),
//!     vec![0, 42]
//! );
//! assert_eq!(
//!     UnionEnum::from_ssz_bytes(&[1, 42]).unwrap(),
//!     UnionEnum::Bar(42),
//! );
//!
//! /// Represented as only the value in the enum variant.
//! #[derive(Debug, PartialEq, Encode)]
//! #[ssz(transparent)]
//! enum TransparentEnum {
//!     Foo(u8),
//!     Bar(Vec<u8>),
//! }
//!
//! assert_eq!(
//!     TransparentEnum::Foo(42).as_ssz_bytes(),
//!     vec![42]
//! );
//! assert_eq!(
//!     TransparentEnum::Bar(vec![42, 42]).as_ssz_bytes(),
//!     vec![42, 42]
//! );
//! ```

use darling::{FromDeriveInput, FromMeta};
use proc_macro::TokenStream;
use quote::quote;
use std::convert::TryInto;
use syn::{parse_macro_input, DataEnum, DataStruct, DeriveInput, Ident};

/// The highest possible union selector value (higher values are reserved for backwards compatible
/// extensions).
const MAX_UNION_SELECTOR: u8 = 127;

const NO_ENUM_BEHAVIOUR_ERROR: &str = "enums require a \"transparent\" or \"union\" attribute, \
    e.g., #[ssz(transparent)] or #[ssz(union)]";

#[derive(Debug, FromDeriveInput)]
#[darling(attributes(ssz))]
struct StructOpts {
    #[darling(default)]
    enum_behaviour: Option<String>,
    #[darling(default)]
    transparent: bool,
    #[darling(default)]
    union: bool,
}

/// Field-level configuration.
#[derive(Debug, Default, FromMeta)]
struct FieldOpts {
    #[darling(default)]
    with: Option<Ident>,
    #[darling(default)]
    skip_serializing: bool,
    #[darling(default)]
    skip_deserializing: bool,
}

struct Config {
    struct_behaviour: StructBehaviour,
    enum_behaviour: EnumBehaviour,
}

impl Config {
    fn read(item: &DeriveInput) -> Self {
        let opts = StructOpts::from_derive_input(item).unwrap();

        let enum_behaviour = match (opts.transparent, opts.union, &opts.enum_behaviour) {
            (false, false, None) => EnumBehaviour::Unspecified,
            (true, false, None) => EnumBehaviour::Transparent,
            (false, true, None) => EnumBehaviour::Union,
            (true, true, _) => panic!("cannot provide both \"transparent\" and \"union\""),
            (_, _, Some(_)) => panic!(
                "the \"enum_behaviour\" attribute has been removed, please use \
                either #[ssz(transparent)] or #[ssz(union)] instead"
            ),
        };

        // Don't allow `enum_behaviour` for structs.
        if matches!(item.data, syn::Data::Struct(_)) && opts.enum_behaviour.is_some() {
            panic!("cannot provide \"enum_behaviour\" for a struct")
        }

        let struct_behaviour = if opts.transparent {
            StructBehaviour::Transparent
        } else {
            StructBehaviour::Container
        };

        Self {
            struct_behaviour,
            enum_behaviour,
        }
    }
}

enum StructBehaviour {
    Transparent,
    Container,
}

enum EnumBehaviour {
    Transparent,
    Union,
    Unspecified,
}

fn parse_ssz_fields(struct_data: &syn::DataStruct) -> Vec<(&syn::Type, &syn::Ident, FieldOpts)> {
    struct_data
        .fields
        .iter()
        .map(|field| {
            let ty = &field.ty;
            let ident = match &field.ident {
                Some(ref ident) => ident,
                _ => panic!("ssz_derive only supports named struct fields."),
            };

            let field_opts_candidates = field
                .attrs
                .iter()
                .filter(|attr| attr.path.get_ident().map_or(false, |ident| *ident == "ssz"))
                .collect::<Vec<_>>();

            if field_opts_candidates.len() > 1 {
                panic!("more than one field-level \"ssz\" attribute provided")
            }

            let field_opts = field_opts_candidates
                .first()
                .map(|attr| {
                    let meta = attr.parse_meta().unwrap();
                    FieldOpts::from_meta(&meta).unwrap()
                })
                .unwrap_or_default();

            (ty, ident, field_opts)
        })
        .collect()
}

/// Implements `ssz::Encode` for some `struct` or `enum`.
#[proc_macro_derive(Encode, attributes(ssz))]
pub fn ssz_encode_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);
    let config = Config::read(&item);

    match &item.data {
        syn::Data::Struct(s) => match config.struct_behaviour {
            StructBehaviour::Transparent => ssz_encode_derive_struct_transparent(&item, s),
            StructBehaviour::Container => ssz_encode_derive_struct(&item, s),
        },
        syn::Data::Enum(s) => match config.enum_behaviour {
            EnumBehaviour::Transparent => ssz_encode_derive_enum_transparent(&item, s),
            EnumBehaviour::Union => ssz_encode_derive_enum_union(&item, s),
            EnumBehaviour::Unspecified => panic!("{}", NO_ENUM_BEHAVIOUR_ERROR),
        },
        _ => panic!("ssz_derive only supports structs and enums"),
    }
}

/// Derive `ssz::Encode` for a struct.
///
/// Fields are encoded in the order they are defined.
///
/// ## Field attributes
///
/// - `#[ssz(skip_serializing)]`: the field will not be serialized.
fn ssz_encode_derive_struct(derive_input: &DeriveInput, struct_data: &DataStruct) -> TokenStream {
    let name = &derive_input.ident;
    let (impl_generics, ty_generics, where_clause) = &derive_input.generics.split_for_impl();

    let field_is_ssz_fixed_len = &mut vec![];
    let field_fixed_len = &mut vec![];
    let field_ssz_bytes_len = &mut vec![];
    let field_encoder_append = &mut vec![];

    for (ty, ident, field_opts) in parse_ssz_fields(struct_data) {
        if field_opts.skip_serializing {
            continue;
        }

        if let Some(module) = field_opts.with {
            let module = quote! { #module::encode };
            field_is_ssz_fixed_len.push(quote! { #module::is_ssz_fixed_len() });
            field_fixed_len.push(quote! { #module::ssz_fixed_len() });
            field_ssz_bytes_len.push(quote! { #module::ssz_bytes_len(&self.#ident) });
            field_encoder_append.push(quote! {
                encoder.append_parameterized(
                    #module::is_ssz_fixed_len(),
                    |buf| #module::ssz_append(&self.#ident, buf)
                )
            });
        } else {
            field_is_ssz_fixed_len.push(quote! { <#ty as ssz::Encode>::is_ssz_fixed_len() });
            field_fixed_len.push(quote! { <#ty as ssz::Encode>::ssz_fixed_len() });
            field_ssz_bytes_len.push(quote! { self.#ident.ssz_bytes_len() });
            field_encoder_append.push(quote! { encoder.append(&self.#ident) });
        }
    }

    let output = quote! {
        impl #impl_generics ssz::Encode for #name #ty_generics #where_clause {
            fn is_ssz_fixed_len() -> bool {
                #(
                    #field_is_ssz_fixed_len &&
                )*
                    true
            }

            fn ssz_fixed_len() -> usize {
                if <Self as ssz::Encode>::is_ssz_fixed_len() {
                    let mut len: usize = 0;
                    #(
                        len = len
                            .checked_add(#field_fixed_len)
                            .expect("encode ssz_fixed_len length overflow");
                    )*
                    len
                } else {
                    ssz::BYTES_PER_LENGTH_OFFSET
                }
            }

            fn ssz_bytes_len(&self) -> usize {
                if <Self as ssz::Encode>::is_ssz_fixed_len() {
                    <Self as ssz::Encode>::ssz_fixed_len()
                } else {
                    let mut len: usize = 0;
                    #(
                        if #field_is_ssz_fixed_len {
                            len = len
                                .checked_add(#field_fixed_len)
                                .expect("encode ssz_bytes_len length overflow");
                        } else {
                            len = len
                                .checked_add(ssz::BYTES_PER_LENGTH_OFFSET)
                                .expect("encode ssz_bytes_len length overflow for offset");
                            len = len
                                .checked_add(#field_ssz_bytes_len)
                                .expect("encode ssz_bytes_len length overflow for bytes");
                        }
                    )*

                    len
                }
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                let mut offset: usize = 0;
                #(
                    offset = offset
                        .checked_add(#field_fixed_len)
                        .expect("encode ssz_append offset overflow");
                )*

                let mut encoder = ssz::SszEncoder::container(buf, offset);

                #(
                    #field_encoder_append;
                )*

                encoder.finalize();
            }
        }
    };
    output.into()
}

/// Derive `ssz::Encode` "transparently" for a struct which has exactly one non-skipped field.
///
/// The single field is encoded directly, making the outermost `struct` transparent.
///
/// ## Field attributes
///
/// - `#[ssz(skip_serializing)]`: the field will not be serialized.
fn ssz_encode_derive_struct_transparent(
    derive_input: &DeriveInput,
    struct_data: &DataStruct,
) -> TokenStream {
    let name = &derive_input.ident;
    let (impl_generics, ty_generics, where_clause) = &derive_input.generics.split_for_impl();
    let ssz_fields = parse_ssz_fields(struct_data);
    let num_fields = ssz_fields
        .iter()
        .filter(|(_, _, field_opts)| !field_opts.skip_deserializing)
        .count();

    if num_fields != 1 {
        panic!(
            "A \"transparent\" struct must have exactly one non-skipped field ({} fields found)",
            num_fields
        );
    }

    let (ty, ident, _field_opts) = ssz_fields
        .iter()
        .find(|(_, _, field_opts)| !field_opts.skip_deserializing)
        .expect("\"transparent\" struct must have at least one non-skipped field");

    let output = quote! {
        impl #impl_generics ssz::Encode for #name #ty_generics #where_clause {
            fn is_ssz_fixed_len() -> bool {
                <#ty as ssz::Encode>::is_ssz_fixed_len()
            }

            fn ssz_fixed_len() -> usize {
                <#ty as ssz::Encode>::ssz_fixed_len()
            }

            fn ssz_bytes_len(&self) -> usize {
                self.#ident.ssz_bytes_len()
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                self.#ident.ssz_append(buf)
            }
        }
    };
    output.into()
}

/// Derive `ssz::Encode` for an enum in the "transparent" method.
///
/// The "transparent" method is distinct from the "union" method specified in the SSZ specification.
/// When using "transparent", the enum will be ignored and the contained field will be serialized as
/// if the enum does not exist. Since an union variant "selector" is not serialized, it is not
/// possible to reliably decode an enum that is serialized transparently.
///
/// ## Limitations
///
/// Only supports:
/// - Enums with a single field per variant, where
///     - All fields are variably sized from an SSZ-perspective (not fixed size).
///
/// ## Panics
///
/// Will panic at compile-time if the single field requirement isn't met, but will panic *at run
/// time* if the variable-size requirement isn't met.
fn ssz_encode_derive_enum_transparent(
    derive_input: &DeriveInput,
    enum_data: &DataEnum,
) -> TokenStream {
    let name = &derive_input.ident;
    let (impl_generics, ty_generics, where_clause) = &derive_input.generics.split_for_impl();

    let (patterns, assert_exprs): (Vec<_>, Vec<_>) = enum_data
        .variants
        .iter()
        .map(|variant| {
            let variant_name = &variant.ident;

            if variant.fields.len() != 1 {
                panic!("ssz::Encode can only be derived for enums with 1 field per variant");
            }

            let pattern = quote! {
                #name::#variant_name(ref inner)
            };

            let ty = &(&variant.fields).into_iter().next().unwrap().ty;
            let type_assert = quote! {
                !<#ty as ssz::Encode>::is_ssz_fixed_len()
            };
            (pattern, type_assert)
        })
        .unzip();

    let output = quote! {
        impl #impl_generics ssz::Encode for #name #ty_generics #where_clause {
            fn is_ssz_fixed_len() -> bool {
                assert!(
                    #(
                        #assert_exprs &&
                    )* true,
                    "not all enum variants are variably-sized"
                );
                false
            }

            fn ssz_bytes_len(&self) -> usize {
                match self {
                    #(
                        #patterns => inner.ssz_bytes_len(),
                    )*
                }
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                match self {
                    #(
                        #patterns => inner.ssz_append(buf),
                    )*
                }
            }
        }
    };
    output.into()
}

/// Derive `ssz::Encode` for an `enum` following the "union" SSZ spec.
///
/// The union selector will be determined based upon the order in which the enum variants are
/// defined. E.g., the top-most variant in the enum will have a selector of `0`, the variant
/// beneath it will have a selector of `1` and so on.
///
/// # Limitations
///
/// Only supports enums where each variant has a single field.
fn ssz_encode_derive_enum_union(derive_input: &DeriveInput, enum_data: &DataEnum) -> TokenStream {
    let name = &derive_input.ident;
    let (impl_generics, ty_generics, where_clause) = &derive_input.generics.split_for_impl();

    let patterns: Vec<_> = enum_data
        .variants
        .iter()
        .map(|variant| {
            let variant_name = &variant.ident;

            if variant.fields.len() != 1 {
                panic!("ssz::Encode can only be derived for enums with 1 field per variant");
            }

            let pattern = quote! {
                #name::#variant_name(ref inner)
            };
            pattern
        })
        .collect();

    let union_selectors = compute_union_selectors(patterns.len());

    let output = quote! {
        impl #impl_generics ssz::Encode for #name #ty_generics #where_clause {
            fn is_ssz_fixed_len() -> bool {
                false
            }

            fn ssz_bytes_len(&self) -> usize {
                match self {
                    #(
                        #patterns => inner
                            .ssz_bytes_len()
                            .checked_add(1)
                            .expect("encoded length must be less than usize::max_value"),
                    )*
                }
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                match self {
                    #(
                        #patterns => {
                            let union_selector: u8 = #union_selectors;
                            debug_assert!(union_selector <= ssz::MAX_UNION_SELECTOR);
                            buf.push(union_selector);
                            inner.ssz_append(buf)
                        },
                    )*
                }
            }
        }
    };
    output.into()
}

/// Derive `ssz::Decode` for a struct or enum.
#[proc_macro_derive(Decode, attributes(ssz))]
pub fn ssz_decode_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);
    let config = Config::read(&item);

    match &item.data {
        syn::Data::Struct(s) => match config.struct_behaviour {
            StructBehaviour::Transparent => ssz_decode_derive_struct_transparent(&item, s),
            StructBehaviour::Container => ssz_decode_derive_struct(&item, s),
        },
        syn::Data::Enum(s) => match config.enum_behaviour {
            EnumBehaviour::Union => ssz_decode_derive_enum_union(&item, s),
            EnumBehaviour::Transparent => panic!(
                "Decode cannot be derived for enum_behaviour \"transparent\", only \"union\" is valid."
            ),
            EnumBehaviour::Unspecified => panic!("{}", NO_ENUM_BEHAVIOUR_ERROR),
        },
        _ => panic!("ssz_derive only supports structs and enums"),
    }
}

/// Implements `ssz::Decode` for some `struct`.
///
/// Fields are decoded in the order they are defined.
///
/// ## Field attributes
///
/// - `#[ssz(skip_deserializing)]`: during de-serialization the field will be instantiated from a
/// `Default` implementation. The decoder will assume that the field was not serialized at all
/// (e.g., if it has been serialized, an error will be raised instead of `Default` overriding it).
fn ssz_decode_derive_struct(item: &DeriveInput, struct_data: &DataStruct) -> TokenStream {
    let name = &item.ident;
    let (impl_generics, ty_generics, where_clause) = &item.generics.split_for_impl();

    let mut register_types = vec![];
    let mut field_names = vec![];
    let mut fixed_decodes = vec![];
    let mut decodes = vec![];
    let mut is_fixed_lens = vec![];
    let mut fixed_lens = vec![];

    for (ty, ident, field_opts) in parse_ssz_fields(struct_data) {
        field_names.push(quote! {
            #ident
        });

        // Field should not be deserialized; use a `Default` impl to instantiate.
        if field_opts.skip_deserializing {
            decodes.push(quote! {
                let #ident = <_>::default();
            });

            fixed_decodes.push(quote! {
                let #ident = <_>::default();
            });

            continue;
        }

        let is_ssz_fixed_len;
        let ssz_fixed_len;
        let from_ssz_bytes;
        if let Some(module) = field_opts.with {
            let module = quote! { #module::decode };

            is_ssz_fixed_len = quote! { #module::is_ssz_fixed_len() };
            ssz_fixed_len = quote! { #module::ssz_fixed_len() };
            from_ssz_bytes = quote! { #module::from_ssz_bytes(slice) };

            register_types.push(quote! {
                builder.register_type_parameterized(#is_ssz_fixed_len, #ssz_fixed_len)?;
            });
            decodes.push(quote! {
                let #ident = decoder.decode_next_with(|slice| #module::from_ssz_bytes(slice))?;
            });
        } else {
            is_ssz_fixed_len = quote! { <#ty as ssz::Decode>::is_ssz_fixed_len() };
            ssz_fixed_len = quote! { <#ty as ssz::Decode>::ssz_fixed_len() };
            from_ssz_bytes = quote! { <#ty as ssz::Decode>::from_ssz_bytes(slice) };

            register_types.push(quote! {
                builder.register_type::<#ty>()?;
            });
            decodes.push(quote! {
                let #ident = decoder.decode_next()?;
            });
        }

        fixed_decodes.push(quote! {
            let #ident = {
                start = end;
                end = end
                    .checked_add(#ssz_fixed_len)
                    .ok_or_else(|| ssz::DecodeError::OutOfBoundsByte {
                        i: usize::max_value()
                    })?;
                let slice = bytes.get(start..end)
                    .ok_or_else(|| ssz::DecodeError::InvalidByteLength {
                        len: bytes.len(),
                        expected: end
                    })?;
                #from_ssz_bytes?
            };
        });
        is_fixed_lens.push(is_ssz_fixed_len);
        fixed_lens.push(ssz_fixed_len);
    }

    let output = quote! {
        impl #impl_generics ssz::Decode for #name #ty_generics #where_clause {
            fn is_ssz_fixed_len() -> bool {
                #(
                    #is_fixed_lens &&
                )*
                    true
            }

            fn ssz_fixed_len() -> usize {
                if <Self as ssz::Decode>::is_ssz_fixed_len() {
                    let mut len: usize = 0;
                    #(
                        len = len
                            .checked_add(#fixed_lens)
                            .expect("decode ssz_fixed_len overflow");
                    )*
                    len
                } else {
                    ssz::BYTES_PER_LENGTH_OFFSET
                }
            }

            fn from_ssz_bytes(bytes: &[u8]) -> std::result::Result<Self, ssz::DecodeError> {
                if <Self as ssz::Decode>::is_ssz_fixed_len() {
                    if bytes.len() != <Self as ssz::Decode>::ssz_fixed_len() {
                        return Err(ssz::DecodeError::InvalidByteLength {
                            len: bytes.len(),
                            expected: <Self as ssz::Decode>::ssz_fixed_len(),
                        });
                    }

                    let mut start: usize = 0;
                    let mut end = start;

                    #(
                        #fixed_decodes
                    )*

                    Ok(Self {
                        #(
                            #field_names,
                        )*
                    })
                } else {
                    let mut builder = ssz::SszDecoderBuilder::new(bytes);

                    #(
                        #register_types
                    )*

                    let mut decoder = builder.build()?;

                    #(
                        #decodes
                    )*


                    Ok(Self {
                        #(
                            #field_names,
                        )*
                    })
                }
            }
        }
    };
    output.into()
}

/// Implements `ssz::Decode` "transparently" for a `struct` with exactly one non-skipped field.
///
/// The bytes will be decoded as if they are the inner field, without the outmost struct. The
/// outermost struct will then be applied artificially.
///
/// ## Field attributes
///
/// - `#[ssz(skip_deserializing)]`: during de-serialization the field will be instantiated from a
/// `Default` implementation. The decoder will assume that the field was not serialized at all
/// (e.g., if it has been serialized, an error will be raised instead of `Default` overriding it).
fn ssz_decode_derive_struct_transparent(
    item: &DeriveInput,
    struct_data: &DataStruct,
) -> TokenStream {
    let name = &item.ident;
    let (impl_generics, ty_generics, where_clause) = &item.generics.split_for_impl();
    let ssz_fields = parse_ssz_fields(struct_data);
    let num_fields = ssz_fields
        .iter()
        .filter(|(_, _, field_opts)| !field_opts.skip_deserializing)
        .count();

    if num_fields != 1 {
        panic!(
            "A \"transparent\" struct must have exactly one non-skipped field ({} fields found)",
            num_fields
        );
    }

    let mut field_names = vec![];
    let mut fields = vec![];
    let mut wrapped_type = None;

    for (ty, ident, field_opts) in ssz_fields {
        field_names.push(quote! {
            #ident
        });

        if field_opts.skip_deserializing {
            fields.push(quote! {
                #ident: <_>::default(),
            });
        } else {
            fields.push(quote! {
                #ident: <_>::from_ssz_bytes(bytes)?,
            });
            wrapped_type = Some(ty);
        }
    }

    let ty = wrapped_type.unwrap();

    let output = quote! {
        impl #impl_generics ssz::Decode for #name #ty_generics #where_clause {
            fn is_ssz_fixed_len() -> bool {
                <#ty as ssz::Decode>::is_ssz_fixed_len()
            }

            fn ssz_fixed_len() -> usize {
                <#ty as ssz::Decode>::ssz_fixed_len()
            }

            fn from_ssz_bytes(bytes: &[u8]) -> std::result::Result<Self, ssz::DecodeError> {
                Ok(Self {
                    #(
                        #fields
                    )*

                })
            }
        }
    };
    output.into()
}

/// Derive `ssz::Decode` for an `enum` following the "union" SSZ spec.
fn ssz_decode_derive_enum_union(derive_input: &DeriveInput, enum_data: &DataEnum) -> TokenStream {
    let name = &derive_input.ident;
    let (impl_generics, ty_generics, where_clause) = &derive_input.generics.split_for_impl();

    let (constructors, var_types): (Vec<_>, Vec<_>) = enum_data
        .variants
        .iter()
        .map(|variant| {
            let variant_name = &variant.ident;

            if variant.fields.len() != 1 {
                panic!("ssz::Encode can only be derived for enums with 1 field per variant");
            }

            let constructor = quote! {
                #name::#variant_name
            };

            let ty = &(&variant.fields).into_iter().next().unwrap().ty;
            (constructor, ty)
        })
        .unzip();

    let union_selectors = compute_union_selectors(constructors.len());

    let output = quote! {
        impl #impl_generics ssz::Decode for #name #ty_generics #where_clause {
            fn is_ssz_fixed_len() -> bool {
                false
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
                // Sanity check to ensure the definition here does not drift from the one defined in
                // `ssz`.
                debug_assert_eq!(#MAX_UNION_SELECTOR, ssz::MAX_UNION_SELECTOR);

                let (selector, body) = ssz::split_union_bytes(bytes)?;

                match selector.into() {
                    #(
                        #union_selectors => {
                            <#var_types as ssz::Decode>::from_ssz_bytes(body).map(#constructors)
                        },
                    )*
                    other => Err(ssz::DecodeError::UnionSelectorInvalid(other))
                }
            }
        }
    };
    output.into()
}

fn compute_union_selectors(num_variants: usize) -> Vec<u8> {
    let union_selectors = (0..num_variants)
        .map(|i| {
            i.try_into()
                .expect("union selector exceeds u8::max_value, union has too many variants")
        })
        .collect::<Vec<u8>>();

    let highest_selector = union_selectors
        .last()
        .copied()
        .expect("0-variant union is not permitted");

    assert!(
        highest_selector <= MAX_UNION_SELECTOR,
        "union selector {} exceeds limit of {}, enum has too many variants",
        highest_selector,
        MAX_UNION_SELECTOR
    );

    union_selectors
}
