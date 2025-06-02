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
    w: usize
}

#[test]
fn test_cool_struct_hmac_works() {
    let data = CoolStruct { x: 5, y: "hi".into(), z: vec![1, 3], w: 5 };

    data.update_hmac(mac);
    let key = String::from("key");

    data.verify_tag(&key, &tag.into_bytes()).expect("tag should be reproducible");
}
