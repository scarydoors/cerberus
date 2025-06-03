use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Field};

#[proc_macro_derive(UpdateHmac, attributes(hmac))]
pub fn derive_update_hmac(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match impl_update_hmac(&input) {
        Ok(tokens) => tokens,
        Err(e) => e.into_compile_error().into(),
    }
}

fn impl_update_hmac(input: &DeriveInput) -> Result<TokenStream, syn::Error> {
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    match &input.data {
        syn::Data::Struct(data) => {
            let name = &input.ident;
            let input_fields = data.fields.iter().enumerate().filter_map(|(i, field)| {
                if has_hmac_skip(&field) {
                    None
                } else {
                    let tokens = match field.ident.as_ref() {
                        Some(ident) => quote! { self.#ident },
                        None => quote! { self.#i },
                    };

                    Some(tokens)
                }
            });

            let expanded = quote! {
                impl #impl_generics UpdateHmac for #name #type_generics #where_clause
                {
                    fn update_hmac(&self, hmac: &mut impl ::hmac::Mac) {
                        #(hmac.update(&::serde_json::to_vec(&#input_fields).expect("data should be serializable"));)*
                    }
                }
            };

            Ok(expanded.into())
        }
        _ => Err(syn::Error::new_spanned(
            input,
            "#[derive(UpdateHmac)] can only be used with structs",
        )),
    }
}

fn has_hmac_skip(field: &Field) -> bool {
    field.attrs.iter().any(|attr| {
        if attr.path().is_ident("hmac") {
            match attr.parse_args::<syn::Path>() {
                Ok(path) => path.is_ident("skip"),
                _ => false,
            }
        } else {
            false
        }
    })
}
