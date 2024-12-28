#[derive(Debug, Clone)]
pub(crate) struct EncryptedData {
    data: Vec<u8>,
    nonce: [u8; 24]
}
