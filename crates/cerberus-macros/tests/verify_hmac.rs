use cerberus_macros::VerifyHmac;

#[derive(VerifyHmac)]
struct CoolStruct {
    x: i32,
    y: String,
}

#[test]
fn test_cool_struct_hmac_works() {

}
