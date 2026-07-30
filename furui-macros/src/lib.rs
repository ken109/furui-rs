extern crate proc_macro;

use std::collections::HashMap;

use itertools::Itertools;
use proc_macro::TokenStream;
use proc_macro2::TokenTree;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

/// Helper attribute understood by both derives.
const SEARCH_KEY: &str = "search_key";

const EXPECTED_FORM: &str = "expected `#[search_key(<policy key field> = <default>)]`";

#[proc_macro_derive(SearchPolicyKey, attributes(search_key))]
pub fn search_policy_key(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input as DeriveInput);
    generate_search_policy_key(&input, false).unwrap_or_else(|err| err.to_compile_error().into())
}

#[proc_macro_derive(SearchIcmpPolicyKey, attributes(search_key))]
pub fn search_icmp_policy_key(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input as DeriveInput);
    generate_search_policy_key(&input, true).unwrap_or_else(|err| err.to_compile_error().into())
}

fn generate_search_policy_key(
    derive_input: &DeriveInput,
    is_icmp: bool,
) -> Result<TokenStream, syn::Error> {
    let struct_data = match &derive_input.data {
        syn::Data::Struct(v) => v,
        _ => {
            return Err(syn::Error::new_spanned(
                &derive_input.ident,
                "Must be struct type",
            ));
        }
    };

    let mut field_defaults = HashMap::new();
    for field in &struct_data.fields {
        let field_name = field.ident.as_ref().ok_or_else(|| {
            syn::Error::new_spanned(&derive_input.ident, "tuple structs are not supported")
        })?;

        for attr in &field.attrs {
            // Fields may carry unrelated attributes; only `search_key` is ours.
            if !attr.path().is_ident(SEARCH_KEY) {
                continue;
            }

            // `#[search_key(<policy key field> = <value when this field is unset>)]`
            let mut tokens = attr.meta.require_list()?.tokens.clone().into_iter();

            let target = tokens
                .next()
                .ok_or_else(|| syn::Error::new_spanned(attr, EXPECTED_FORM))?;
            match tokens.next() {
                Some(TokenTree::Punct(punct)) if punct.as_char() == '=' => {}
                _ => return Err(syn::Error::new_spanned(attr, EXPECTED_FORM)),
            }
            let default = tokens.collect::<proc_macro2::TokenStream>();
            if default.is_empty() {
                return Err(syn::Error::new_spanned(attr, EXPECTED_FORM));
            }

            field_defaults.insert(field_name, (target, default));
        }
    }

    let mut sections = Vec::new();
    for i in 1..=field_defaults.len() {
        for use_fields in field_defaults.keys().into_iter().combinations(i) {
            for (field_name, (target, value)) in field_defaults.clone() {
                if use_fields.contains(&&field_name) {
                    sections.push(quote! {
                        policy_key.#target = self.#field_name;
                    });
                } else {
                    sections.push(quote! {
                        policy_key.#target = #value;
                    });
                }
            }
            sections.push(quote! {
                if callback(policy_key) {
                    return true;
                };
            });
        }
    }

    let struct_name = &derive_input.ident;

    let policy_key_name = if is_icmp {
        quote!(IcmpPolicyKey)
    } else {
        quote!(PolicyKey)
    };

    Ok(quote!(
        impl #struct_name {
            pub fn search_key<F: Fn(&#policy_key_name) -> bool>(
                &mut self,
                policy_key: &mut #policy_key_name,
                callback: F,
            ) -> bool {
                #(#sections)*

                false
            }
        }
    )
    .into())
}
