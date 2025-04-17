use anyhow::Result;

use cerberus_daemon::get_socket_path;
use cerberus_daemon::server::Server;
use tokio::{io::{AsyncBufReadExt, BufReader}, net::UnixStream};

#[tokio::main]
async fn main() -> Result<()> {
    let path = get_socket_path();

    let server = Server::bind(&path).await?;

    server.run().await?;
    Ok(())
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
