use std::{error::Error, fmt, io::Error as IoError};

pub struct CudaClientError {
    variant: CudaClientErrorVariant,
    ctx: Option<String>,
}

impl fmt::Display for CudaClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CudaClientError: {}", self.variant)
    }
}

impl fmt::Debug for CudaClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "CudaClientError: {:?}", self.variant)?;
        if let Some(ctx) = &self.ctx {
            writeln!(f, "Context: {ctx:?}")?;
        }
        Ok(())
    }
}

impl Error for CudaClientError {}

impl CudaClientError {
    pub const fn new(variant: CudaClientErrorVariant) -> Self {
        Self { variant, ctx: None }
    }

    pub fn new_with_ctx(variant: CudaClientErrorVariant, ctx: impl Into<String>) -> Self {
        Self { variant, ctx: Some(ctx.into()) }
    }

    pub fn context(&mut self, ctx: impl Into<String>) {
        self.ctx = Some(ctx.into());
    }
}

#[allow(non_snake_case)]
impl CudaClientError {
    pub const fn Connect(err: IoError) -> Self {
        Self::new(CudaClientErrorVariant::Connect(err))
    }

    pub fn new_connect(err: IoError, ctx: &str) -> Self {
        Self::new_with_ctx(CudaClientErrorVariant::Connect(err), ctx)
    }

    pub const fn Serialize(err: bincode::Error) -> Self {
        Self::new(CudaClientErrorVariant::Serialize(err))
    }

    pub fn new_serialize(err: bincode::Error, ctx: &str) -> Self {
        Self::new_with_ctx(CudaClientErrorVariant::Serialize(err), ctx)
    }

    pub const fn Deserialize(err: bincode::Error) -> Self {
        Self::new(CudaClientErrorVariant::Deserialize(err))
    }

    pub fn new_deserialize(err: bincode::Error, ctx: &str) -> Self {
        Self::new_with_ctx(CudaClientErrorVariant::Deserialize(err), ctx)
    }

    pub const fn Write(err: IoError) -> Self {
        Self::new(CudaClientErrorVariant::Write(err))
    }

    pub fn new_write(err: IoError, ctx: &str) -> Self {
        Self::new_with_ctx(CudaClientErrorVariant::Write(err), ctx)
    }

    pub fn Read(err: IoError) -> Self {
        Self::new(CudaClientErrorVariant::Read(err))
    }

    pub fn new_read(err: IoError, ctx: &str) -> Self {
        Self::new_with_ctx(CudaClientErrorVariant::Read(err), ctx)
    }

    pub const fn ServerError(err: String) -> Self {
        Self::new(CudaClientErrorVariant::ServerError(err))
    }

    pub fn new_server_error(err: String, ctx: &str) -> Self {
        Self::new_with_ctx(CudaClientErrorVariant::ServerError(err), ctx)
    }

    pub const fn UnexpectedResponse(response: &'static str) -> Self {
        Self::new(CudaClientErrorVariant::UnexpectedResponse(response))
    }

    pub fn new_unexpected_response(response: &'static str, ctx: &str) -> Self {
        Self::new_with_ctx(CudaClientErrorVariant::UnexpectedResponse(response), ctx)
    }

    pub const fn ProverError(err: String) -> Self {
        Self::new(CudaClientErrorVariant::ProverError(err))
    }

    pub fn new_prover_error(err: String, ctx: &str) -> Self {
        Self::new_with_ctx(CudaClientErrorVariant::ProverError(err), ctx)
    }

    pub const fn Download(err: reqwest::Error) -> Self {
        Self::new(CudaClientErrorVariant::Download(err))
    }

    pub fn new_download(err: reqwest::Error, ctx: &str) -> Self {
        Self::new_with_ctx(CudaClientErrorVariant::Download(err), ctx)
    }

    pub const fn DownloadIO(err: IoError) -> Self {
        Self::new(CudaClientErrorVariant::DownloadIO(err))
    }

    pub fn new_download_io(err: IoError, ctx: &str) -> Self {
        Self::new_with_ctx(CudaClientErrorVariant::DownloadIO(err), ctx)
    }

    pub const fn Unexpected(err: String) -> Self {
        Self::new(CudaClientErrorVariant::Unexpected(err))
    }

    pub fn new_unexpected(err: String, ctx: &str) -> Self {
        Self::new_with_ctx(CudaClientErrorVariant::Unexpected(err), ctx)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CudaClientErrorVariant {
    #[error("Failed to connect to the server: {0:?}")]
    Connect(IoError),

    #[error("Failed to serialize the request: {0:?}")]
    Serialize(bincode::Error),

    #[error("Failed to deserialize the response: {0:?}")]
    Deserialize(bincode::Error),

    #[error("Failed to write the request: {0:?}")]
    Write(IoError),

    #[error("Failed to read the response: {0:?}")]
    Read(IoError),

    #[error("The server returned an internal error \n {0}")]
    ServerError(String),

    #[error("The server returned an unexpected response: {0:?}")]
    UnexpectedResponse(&'static str),

    #[error("The server returned a prover error: {0:?}")]
    ProverError(String),

    #[error("Failed to download the server: {0:?}")]
    Download(#[from] reqwest::Error),

    #[error("Failed to download the server: {0:?}")]
    DownloadIO(std::io::Error),

    #[error("Unexpected error: {0:?}")]
    Unexpected(String),
}
