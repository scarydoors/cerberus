use cerberus_daemon::get_socket_path;
use anyhow::Result;
use tokio::{io::AsyncWriteExt, net::UnixStream};

#[tokio::main]
async fn main() -> Result<()> {
    let stream = UnixStream::connect(get_socket_path()).await?;
    let (reader, mut writer) = stream.into_split();

    writer.write_all(b"what\n").await?;

    Ok(())
}
