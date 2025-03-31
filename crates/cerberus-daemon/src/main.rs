use std::fs;
use anyhow::Result;

use cerberus_daemon::get_socket_path;
use tokio::{io::{AsyncBufReadExt, AsyncReadExt, BufReader}, net::{UnixListener, UnixStream}};

#[tokio::main]
async fn main() -> Result<()> {
    let path = get_socket_path();

    if path.exists() {
        fs::remove_file(&path)?;
    }

    let listener = UnixListener::bind(&path)?;

    println!("listening on {}", path.display());

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(handle_client(stream));
    }
}

async fn handle_client(stream: UnixStream) -> Result<()> {
    let (reader, mut _writer) = stream.into_split();

    let reader = BufReader::new(reader);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        println!("{}", line);
    }

    Ok(())
}
