use cerberus_crypto::mac::UpdateHmac;
use cerberus_macros::UpdateHmac as UpdateHmacDerive;

#[allow(dead_code)]
#[derive(UpdateHmacDerive)]
struct CoolStruct {
    #[hmac(skip)]
    x: i32,
    y: String,
    z: Vec<u32>,
    w: usize,
}
