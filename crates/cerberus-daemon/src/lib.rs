use std::{path::PathBuf, env};

pub fn get_socket_path() -> PathBuf {
    // TODO: support more than just macos
    let mut tempdir = PathBuf::from(env::var("TMPDIR").unwrap());
    tempdir.push("cerberus");
    tempdir
}

pub fn test() {
    println!("Hello, world!");
}
