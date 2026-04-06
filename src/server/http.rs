pub mod accept;
pub mod tls;

mod auth;
mod error;
mod genca;

use std::{
    io::{self},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use http::{StatusCode, header, uri::Authority};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{Method, Request, Response, body::Incoming, service::service_fn, upgrade::Upgraded};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
};
use tracing::{Level, instrument};

use self::{
    accept::{Accept, DefaultAcceptor},
    auth::Authenticator,
    error::Error,
    tls::{RustlsAcceptor, RustlsConfig},
};
use super::{Acceptor, Connector, Context, Server};
use crate::ext::Extension;

/// HTTP acceptor.
#[derive(Clone)]
pub struct HttpAcceptor<A = DefaultAcceptor> {
    acceptor: A,
    timeout: Duration,
    handler: Handler,
    builder: Builder<TokioExecutor>,
}

/// HTTP server.
pub struct HttpServer<A = DefaultAcceptor> {
    listener: TcpListener,
    inner: HttpAcceptor<A>,
}

// ===== impl HttpAcceptor =====

impl HttpAcceptor {
    /// Create a new [`HttpAcceptor`] instance.
    pub fn new(ctx: Context) -> HttpAcceptor {
        let acceptor = DefaultAcceptor::new();
        let timeout = Duration::from_secs(ctx.connect_timeout);
        let handler = Handler::from(ctx);

        let mut builder = Builder::new(TokioExecutor::new());
        builder
            .http1()
            .title_case_headers(true)
            .preserve_header_case(true);

        HttpAcceptor {
            acceptor,
            timeout,
            handler,
            builder,
        }
    }

    /// Enable HTTPS with TLS certificate and private key files.
    pub fn with_https<P>(
        self,
        tls_cert: P,
        tls_key: P,
    ) -> std::io::Result<HttpAcceptor<RustlsAcceptor>>
    where
        P: Into<Option<PathBuf>>,
    {
        let config = match (tls_cert.into(), tls_key.into()) {
            (Some(cert), Some(key)) => RustlsConfig::from_pem_chain_file(cert, key),
            _ => {
                let (cert, key) = genca::get_self_signed_cert().map_err(io::Error::other)?;
                RustlsConfig::from_pem(cert, key)
            }
        }?;

        let acceptor = RustlsAcceptor::new(config, self.timeout);
        Ok(HttpAcceptor {
            acceptor,
            timeout: self.timeout,
            handler: self.handler,
            builder: self.builder,
        })
    }
}

// ===== impl HttpServer =====

impl HttpServer {
    /// Create a new [`HttpServer`] instance.
    pub fn new(ctx: Context) -> std::io::Result<HttpServer<DefaultAcceptor>> {
        let socket = if ctx.bind.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };

        socket.set_nodelay(true)?;
        socket.set_reuseaddr(true)?;
        socket.bind(ctx.bind)?;
        socket.listen(ctx.concurrent).map(|listener| HttpServer {
            listener,
            inner: HttpAcceptor::new(ctx),
        })
    }

    /// Enable HTTPS with TLS certificate and private key files.
    pub fn with_https<P>(
        self,
        tls_cert: P,
        tls_key: P,
    ) -> std::io::Result<HttpServer<RustlsAcceptor>>
    where
        P: Into<Option<PathBuf>>,
    {
        self.inner
            .with_https(tls_cert, tls_key)
            .map(|inner| HttpServer {
                listener: self.listener,
                inner,
            })
    }
}

impl<A> Server for HttpServer<A>
where
    A: Accept<TcpStream> + Clone + Send + Sync + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send,
    A::Future: Send,
{
    async fn start(mut self) -> std::io::Result<()> {
        tracing::info!(
            "Http(s) proxy server listening on {}",
            self.listener.local_addr()?
        );

        loop {
            // Accept a new connection
            let conn = HttpServer::<A>::incoming(&mut self.listener).await;
            tokio::spawn(self.inner.clone().accept(conn));
        }
    }
}

impl<A> Acceptor for HttpAcceptor<A>
where
    A: Accept<TcpStream> + Clone + Send + Sync + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send,
    A::Future: Send,
{
    async fn accept(self, (stream, socket_addr): (TcpStream, SocketAddr)) {
        let acceptor = self.acceptor.clone();
        let builder = self.builder.clone();
        let handler = self.handler.clone();

        if let Ok(stream) = acceptor.accept(stream).await {
            if let Err(err) = builder
                .serve_connection_with_upgrades(
                    TokioIo::new(stream),
                    service_fn(|req| <Handler as Clone>::clone(&handler).proxy(socket_addr, req)),
                )
                .await
            {
                tracing::debug!("[HTTP] failed to serve connection: {:?}", err);
            }
        }
    }
}

#[derive(Clone)]
struct Handler {
    authenticator: Arc<Authenticator>,
    connector: Connector,
}

impl From<Context> for Handler {
    fn from(ctx: Context) -> Self {
        let authenticator = match (ctx.auth.username, ctx.auth.password) {
            (Some(username), Some(password)) => Authenticator::Password { username, password },
            _ => Authenticator::None,
        };

        Handler {
            authenticator: Arc::new(authenticator),
            connector: ctx.connector,
        }
    }
}

impl Handler {
    #[instrument(skip(self), level = Level::DEBUG)]
    async fn proxy(
        self,
        socket: SocketAddr,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error> {
        // Check if the client is authorized
        let extension = match self.authenticator.authenticate(req.headers()).await {
            Ok(extension) => extension,
            // If the client is not authorized, return an error response
            Err(err) => {
                let resp = match err {
                    Error::ProxyAuthenticationRequired => Response::builder()
                        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                        .header(header::PROXY_AUTHENTICATE, "Basic realm=\"Proxy\"")
                        .body(empty()),
                    Error::Forbidden => Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(empty()),
                    _ => Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(empty()),
                }?;

                return Ok(resp);
            }
        };

        if Method::CONNECT == req.method() {
            // RFC 9110: establish the outbound tunnel to the authority, then respond with 2xx.
            // Dialing after 200 lets clients start TLS while we still connect; their handshake
            // then stalls until we relay (seen as CONNECT/TLS timeouts for slow or stuck dials).
            if let Some(authority) = req.uri().authority().cloned() {
                let request_line = format!("{} {} {:?}", req.method(), req.uri(), req.version());
                let connector_tcp = self.connector.tcp(extension);
                match connector_tcp.connect(authority.clone()).await {
                    Ok(mut server) => {
                        tokio::spawn(async move {
                            match hyper::upgrade::on(req).await {
                                Ok(upgraded) => {
                                    if let Err(e) =
                                        tunnel(socket, authority, upgraded, server).await
                                    {
                                        tracing::warn!(
                                            "[HTTP] CONNECT tunnel error client={} err={}",
                                            socket,
                                            e
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!("[HTTP] upgrade error: {}", e);
                                    let _ = server.shutdown().await;
                                }
                            }
                        });
                        let mut resp = Response::new(empty());
                        *resp.status_mut() = StatusCode::OK;
                        Ok(resp)
                    }
                    Err(e) => {
                        tracing::warn!(
                            "[HTTP] CONNECT outbound failed client={} line={} authority={} err={}",
                            socket,
                            request_line,
                            authority,
                            e
                        );
                        let mut resp = Response::new(full("outbound connection failed"));
                        *resp.status_mut() = StatusCode::BAD_GATEWAY;
                        Ok(resp)
                    }
                }
            } else {
                tracing::warn!("[HTTP] CONNECT missing authority: {:?}", req.uri());
                let mut resp = Response::new(full("CONNECT must be to a socket address"));
                *resp.status_mut() = StatusCode::BAD_REQUEST;

                Ok(resp)
            }
        } else {
            self.connector
                .http(extension)
                .send_request(req)
                .await
                .map(|res| res.map(|b| b.boxed()))
                .map_err(Into::into)
        }
    }
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

// Relay bytes between the upgraded client connection and an already-connected outbound stream.
async fn tunnel(
    source: SocketAddr,
    target: Authority,
    upgraded: Upgraded,
    mut server: TcpStream,
) -> std::io::Result<()> {
    tracing::info!("[HTTP] {source} -> {target} forwarding connection");

    #[cfg(target_os = "linux")]
    let res =
        match hyper_util::server::conn::auto::upgrade::downcast::<TokioIo<TcpStream>>(upgraded) {
            Ok(io) => {
                let mut client = io.io.into_inner();
                let res = super::io::copy_bidirectional(&mut client, &mut server).await;
                client.shutdown().await?;
                res
            }
            Err(upgraded) => {
                tokio::io::copy_bidirectional(&mut TokioIo::new(upgraded), &mut server).await
            }
        };

    #[cfg(not(target_os = "linux"))]
    let res = tokio::io::copy_bidirectional(&mut TokioIo::new(upgraded), &mut server).await;

    match res {
        Ok((from_client, from_server)) => {
            tracing::info!(
                "[HTTP] client wrote {} bytes and received {} bytes",
                from_client,
                from_server
            );
        }
        Err(err) => {
            tracing::trace!("[HTTP] tunnel error: {}", err);
        }
    }

    server.shutdown().await
}
