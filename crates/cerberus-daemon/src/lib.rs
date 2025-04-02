use std::{path::PathBuf, env};

pub mod server;

fn get_euid() -> u32 {
    unsafe { libc::geteuid() }
}

pub fn get_socket_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    let base_dir = PathBuf::from(
        env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string())
    );

    #[cfg(target_os = "linux")]
    let base_dir = {
        PathBuf::from("/tmp")
    };

    let socket_dir_name = format!("cerberus{}", get_euid());

    base_dir
        .join(socket_dir_name)
        .join("agent")
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("unable to bind socket")]
    UnableToBindSocket(#[from] std::io::Error),
}
