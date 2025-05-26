use cerberus_crypto::mac::VerifyHmac;
use cerberus_macros::VerifyHmac as VerifyHmacDerive;

#[allow(dead_code)]
#[derive(VerifyHmacDerive)]
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

    let key = String::from("key");
    let tag = data.compute_tag(&key);

    data.verify_tag(&key, &tag.into_bytes()).expect("tag should be reproducible");
}
