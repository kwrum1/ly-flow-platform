use async_trait::async_trait;
use bytes::Bytes;
use log::{error, info};
use pingora::http::ResponseHeader;
use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;
use pingora::proxy::{http_proxy_service, ProxyHttp, Session};
use pingora::server::configuration::Opt;
use pingora::server::Server;
use pingora::upstreams::peer::HttpPeer;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Component, Path, PathBuf};
use std::thread;

#[derive(Clone)]
struct Frontend {
    web_root: PathBuf,
    upstream_host: String,
    upstream_port: u16,
}

impl Frontend {
    fn resolve(&self, request_path: &str) -> Option<PathBuf> {
        let path = request_path.split('?').next().unwrap_or("/");
        let relative = Path::new(path).strip_prefix("/").ok()?;
        if relative.components().any(|component| {
            matches!(component, Component::ParentDir | Component::RootDir | Component::Prefix(_))
        }) {
            return None;
        }
        let candidate = self.web_root.join(relative);
        if candidate.is_file() {
            return Some(candidate);
        }
        let index = self.web_root.join("index.html");
        index.is_file().then_some(index)
    }

    fn content_type(path: &Path) -> &'static str {
        match path.extension().and_then(|value| value.to_str()).unwrap_or("") {
            "html" => "text/html; charset=utf-8",
            "js" | "mjs" => "application/javascript; charset=utf-8",
            "css" => "text/css; charset=utf-8",
            "json" => "application/json",
            "svg" => "image/svg+xml",
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            "ico" => "image/x-icon",
            "woff" => "font/woff",
            "woff2" => "font/woff2",
            "map" => "application/json",
            _ => "application/octet-stream",
        }
    }
}

#[async_trait]
impl ProxyHttp for Frontend {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> pingora::Result<bool> {
        let path = session.req_header().uri.path();
        if path.starts_with("/api/") || path.starts_with("/ws/") {
            return Ok(false);
        }
        let Some(file) = self.resolve(path) else {
            session.respond_error(404).await?;
            return Ok(true);
        };
        let body = match std::fs::read(&file) {
            Ok(body) => body,
            Err(_) => {
                session.respond_error(404).await?;
                return Ok(true);
            }
        };
        let mut header = ResponseHeader::build(200, None)?;
        header.insert_header("Content-Type", Self::content_type(&file))?;
        header.insert_header("X-Content-Type-Options", "nosniff")?;
        header.insert_header("Cache-Control", "no-cache")?;
        header.insert_header("Content-Length", body.len().to_string())?;
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        let peer = HttpPeer::new(
            (self.upstream_host.as_str(), self.upstream_port),
            false,
            self.upstream_host.clone(),
        );
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        // The backend is reached over HTTP; preserve the browser-facing scheme
        // for install-script/API URL generation.
        upstream_request.insert_header("X-Forwarded-Proto", "https")?;
        Ok(())
    }
}

fn start_http_redirect() {
    thread::spawn(|| {
        let listener = match TcpListener::bind("0.0.0.0:80") {
            Ok(listener) => listener,
            Err(error) => {
                error!("HTTP redirect listener unavailable: {error}");
                return;
            }
        };
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = match stream.try_clone() {
                Ok(stream) => BufReader::new(stream),
                Err(_) => continue,
            };
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                continue;
            }
            let mut host = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() || line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some(value) = line.strip_prefix("Host:") {
                    host = value.trim().to_string();
                }
            }
            if host.is_empty() {
                host = "localhost".into();
            }
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("/")
                .to_string();
            let _ = write!(
                stream,
                "HTTP/1.1 308 Permanent Redirect\r\nLocation: https://{host}{path}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.flush();
        }
    });
}

fn main() {
    env_logger::init();
    let root = std::env::var("LYFLOW_WEB_ROOT").unwrap_or_else(|_| "/usr/share/lyflow/web".into());
    let upstream_host = std::env::var("LY_SERVER_HOST").unwrap_or_else(|_| "ly-server".into());
    let upstream_port = std::env::var("LY_SERVER_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8080);
    let cert = std::env::var("LYFLOW_TLS_CERT").unwrap_or_else(|_| "/etc/lyflow/ssl/lyflow.crt".into());
    let key = std::env::var("LYFLOW_TLS_KEY").unwrap_or_else(|_| "/etc/lyflow/ssl/lyflow.key".into());

    start_http_redirect();
    let opt = Opt::parse_args();
    let mut server = Server::new(Some(opt)).expect("create Pingora server");
    server.bootstrap();
    let mut proxy = http_proxy_service(
        &server.configuration,
        Frontend {
            web_root: PathBuf::from(root),
            upstream_host,
            upstream_port,
        },
    );
    let tls = TlsSettings::intermediate(&cert, &key).expect("load TLS certificate");
    proxy.add_tls_with_settings("0.0.0.0:443", None, tls);
    server.add_service(proxy);
    info!("LyFlow Pingora frontend listening on :443 (HTTP :80 redirect)");
    server.run_forever();
}
