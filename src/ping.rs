use crate::{error::Error, profile::PingTarget};
use reqwest::{Client, StatusCode};
use tokio::time::{Duration, Instant, sleep};

pub async fn ping_targets(targets: &[PingTarget]) -> Result<(), Error> {
    for target in targets {
        ping_target(target).await?;
    }
    Ok(())
}

pub async fn ping_target(target: &PingTarget) -> Result<(), Error> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|err| Error::HttpPing(err.to_string()))?;

    let deadline = Instant::now() + Duration::from_secs(target.timeout_seconds);
    loop {
        match client.get(&target.url).send().await {
            Ok(response) if response.status() == StatusCode::OK => return Ok(()),
            Ok(response) => {
                if Instant::now() >= deadline {
                    return Err(Error::HttpPing(format!(
                        "{} returned status {}",
                        target.name,
                        response.status()
                    )));
                }
            }
            Err(err) => {
                if Instant::now() >= deadline {
                    return Err(Error::HttpPing(format!("{}: {}", target.name, err)));
                }
            }
        }
        sleep(Duration::from_millis(target.interval_millis)).await;
    }
}

pub async fn ping_target_once(client: &Client, target: &PingTarget) -> Result<(), Error> {
    match client.get(&target.url).send().await {
        Ok(response) if response.status() == StatusCode::OK => Ok(()),
        Ok(response) => Err(Error::HttpPing(format!(
            "{} returned status {}",
            target.name,
            response.status()
        ))),
        Err(err) => Err(Error::HttpPing(format!("{}: {}", target.name, err))),
    }
}

#[cfg(test)]
mod tests {
    use super::{ping_target, ping_target_once};
    use crate::profile::PingTarget;
    use reqwest::Client;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    #[tokio::test]
    async fn ping_target_succeeds_for_http_200() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
        });

        let target = PingTarget {
            name: "api".to_string(),
            url: format!("http://{}", addr),
            timeout_seconds: 1,
            interval_millis: 25,
        };

        ping_target(&target).await.unwrap();
        server.join().unwrap();
    }

    #[tokio::test]
    async fn ping_target_fails_for_non_200() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer);
            stream
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nnope")
                .unwrap();
        });

        let target = PingTarget {
            name: "api".to_string(),
            url: format!("http://{}", addr),
            timeout_seconds: 1,
            interval_millis: 25,
        };

        let client = Client::builder().build().unwrap();
        let err = ping_target_once(&client, &target).await.unwrap_err();
        assert!(err.to_string().contains("503"));
        server.join().unwrap();
    }
}
