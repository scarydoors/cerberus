use cerberus_core::vault::{Vault, Item};
use cerberus_core::primitive::Cipher;
fn main() {
    let mut vault = Vault::new("hi");
    let mut vault = vault.unlock(b"hii");
    let keychain = vault.keychain();
    vault.add_item()
}
