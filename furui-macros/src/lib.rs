extern crate proc_macro;

use proc_macro::TokenStream;
use std::collections::HashMap;

use itertools::Itertools;
use proc_macro2::{Delimiter, TokenTree};
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(SearchPolicyKey, attributes(search_key))]
pub fn search_policy_key(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input as DeriveInput);
    match generate_search_policy_key(&input, false) {
        Ok(generated) => generated,
        Err(err) => err.to_compile_error().into(),
    }
}

#[proc_macro_derive(SearchIcmpPolicyKey, attributes(search_key))]
pub fn search_icmp_policy_key(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input as DeriveInput);
    match generate_search_policy_key(&input, true) {
        Ok(generated) => generated,
        Err(err) => err.to_compile_error().into(),
    }
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
        let filed_name = field.ident.as_ref().unwrap();

        for attr in &field.attrs {
            let mut tokens = attr.tokens.clone().into_iter();
            match [tokens.next(), tokens.next()] {
                [Some(TokenTree::Group(group)), None]
                    if group.delimiter() == Delimiter::Parenthesis =>
                {
                    let mut group_stream = group.stream().into_iter();
                    let target = group_stream.next().unwrap();
                    group_stream.next();

                    field_defaults.insert(
                        filed_name,
                        (
                            target,
                            group_stream
                                .collect_vec()
                                .into_iter()
                                .collect::<proc_macro2::TokenStream>(),
                        ),
                    );
                }
                _ => {
                    return Err(syn::Error::new_spanned(
                        &derive_input.ident,
                        "malformed derive",
                    ))
                }
            }
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
        "IcmpPolicyKey"
    } else {
        "PolicyKey"
    }
    .parse::<proc_macro2::TokenStream>()
    .unwrap();

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
