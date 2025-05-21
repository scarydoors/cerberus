use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(VerifyHmac)]
pub fn derive_verify_hmac(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    impl_verify_hmac(&input)
}

fn impl_verify_hmac(input: &DeriveInput) -> TokenStream {
    let name = &input.ident;

    let fields = match &input.data {
    }
}
