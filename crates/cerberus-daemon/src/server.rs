use crate::Error;
use std::{path::Path};
use tokio::{fs, io::{AsyncBufReadExt, BufReader}, net::{UnixListener, UnixStream}};

struct State {
    master_key: [u8; 32]
}

pub struct Server {
    listener: UnixListener
}

impl Server {
    pub async fn bind(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path_ref = path.as_ref();

        fs::create_dir_all(path_ref.parent().unwrap()).await?;
        fs::remove_file(path_ref).await
            .or_else(
                |e| if e.kind() != std::io::ErrorKind::NotFound { Err(e) } else { Ok(()) }
            )?;

        let listener = UnixListener::bind(path)?;

        Ok(Self {
            listener
        })
    }

    pub async fn run(self) -> Result<(), Error> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            tokio::spawn(Self::handle_connection(stream));
        }
    }

    async fn handle_connection(stream: UnixStream) -> Result<(), Error> {
        let (reader, writer) = stream.into_split();

        let mut line_buffer = String::with_capacity(512);
        let mut buf_reader = BufReader::new(reader);

        loop {
            match buf_reader.read_line(&mut line_buffer).await {
                Ok(0) => break,
                Ok(_) => {
                    println!("{}", line_buffer);
                }
                Err(e) => {
                    return Err(e.into());
                }
            }


            line_buffer.clear();
        }
        Ok(())
    }
}
