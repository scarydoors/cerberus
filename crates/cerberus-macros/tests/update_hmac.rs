use cerberus_crypto::mac::UpdateHmac;
use cerberus_macros::UpdateHmac as UpdateHmacDerive;
use hmac::digest::KeyInit;

#[allow(dead_code)]
#[derive(UpdateHmacDerive)]
struct CoolStruct {
    #[hmac(skip)]
    x: i32,
    y: String,
    z: Vec<u32>,
    w: usize,
}
