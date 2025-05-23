use std::error::Error;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(VerifyHmac)]
pub fn derive_verify_hmac(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match impl_verify_hmac(&input) {
        Ok(tokens) => tokens,
        Err(e) => e.into_compile_error().into()
    }
}

fn impl_verify_hmac(input: &DeriveInput) -> Result<TokenStream, syn::Error> {
    match &input.data {
        syn::Data::Struct(_) => {

        },
        _ => Err(syn::Error::new_spanned(input, "#[derive(VerifyHmac)] can only be used with structs"))
    }
}
