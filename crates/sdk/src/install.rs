//! # SP1 Install
//!
//! A library for installing the SP1 circuit artifacts.

use cfg_if::cfg_if;
use std::path::PathBuf;

#[cfg(any(feature = "network", feature = "network"))]
use {
    futures::StreamExt,
    indicatif::{ProgressBar, ProgressStyle},
    reqwest::Client,
    std::cmp::min,
    tokio::io::AsyncWriteExt,
    tokio::process::Command,
};

use crate::SP1_CIRCUIT_VERSION;

/// The base URL for the S3 bucket containing the circuit artifacts.
pub const CIRCUIT_ARTIFACTS_URL_BASE: &str = "https://sp1-circuits.s3-us-east-2.amazonaws.com";

/// The directory where the groth16 circuit artifacts will be stored.
#[must_use]
pub fn groth16_circuit_artifacts_dir() -> PathBuf {
    std::env::var("SP1_GROTH16_CIRCUIT_PATH")
        .map_or_else(
            |_| dirs::home_dir().unwrap().join(".sp1").join("circuits/groth16"),
            |path| path.parse().unwrap(),
        )
        .join(SP1_CIRCUIT_VERSION)
}

/// The directory where the plonk circuit artifacts will be stored.
#[must_use]
pub fn plonk_circuit_artifacts_dir() -> PathBuf {
    std::env::var("SP1_PLONK_CIRCUIT_PATH")
        .map_or_else(
            |_| dirs::home_dir().unwrap().join(".sp1").join("circuits/plonk"),
            |path| path.parse().unwrap(),
        )
        .join(SP1_CIRCUIT_VERSION)
}

/// Tries to install the groth16 circuit artifacts if they are not already installed.
#[must_use]
pub async fn try_install_circuit_artifacts(artifacts_type: &str) -> PathBuf {
    let build_dir = if artifacts_type == "groth16" {
        groth16_circuit_artifacts_dir()
    } else if artifacts_type == "plonk" {
        plonk_circuit_artifacts_dir()
    } else {
        unimplemented!("unsupported artifacts type: {}", artifacts_type);
    };

    if build_dir.exists() {
        eprintln!(
            "[sp1] {} circuit artifacts already seem to exist at {}. if you want to re-download them, delete the directory",
            artifacts_type,
            build_dir.display()
        );
    } else {
        cfg_if! {
            if #[cfg(any(feature = "network", feature = "network"))] {
                eprintln!(
                    "[sp1] {} circuit artifacts for version {} do not exist at {}. downloading...",
                    artifacts_type,
                    SP1_CIRCUIT_VERSION,
                    build_dir.display()
                );

                install_circuit_artifacts(build_dir.clone(), artifacts_type).await;
            }
        }
    }
    build_dir
}

/// Install the latest circuit artifacts.
///
/// This function will download the latest circuit artifacts from the S3 bucket and extract them
/// to the directory specified by [`groth16_bn254_artifacts_dir()`].
#[cfg(any(feature = "network", feature = "network"))]
#[allow(clippy::needless_pass_by_value)]
pub async fn install_circuit_artifacts(build_dir: PathBuf, artifacts_type: &str) {
    // Create the build directory.
    std::fs::create_dir_all(&build_dir).expect("failed to create build directory");

    // Download the artifacts.
    let download_url =
        format!("{CIRCUIT_ARTIFACTS_URL_BASE}/{SP1_CIRCUIT_VERSION}-{artifacts_type}.tar.gz");

    // Create a tempfile with a name to store the tar in.
    let artifacts_tar_gz_file = tempfile::NamedTempFile::new().expect("failed to create tempfile");

    // Get the path of the tempfile.
    let tar_path =
        artifacts_tar_gz_file.path().to_str().expect("A named file should have a path").to_owned();

    // Create a tokio friendly file to write the tarball to.
    let mut file = tokio::fs::File::from_std(artifacts_tar_gz_file.into_file());

    // Download the file.
    let client = Client::builder().build().expect("failed to create reqwest client");
    download_file(&client, &download_url, &mut file).await.expect("failed to download file");

    // Extract the tarball to the build directory.
    let res = Command::new("tar")
        .args(["-Pxzf", &tar_path, "-C", build_dir.to_str().unwrap()])
        .output()
        .await
        .expect("failed to extract tarball");

    if !res.status.success() {
        panic!("[sp1] failed to extract tarball to {:?}", build_dir.to_str().unwrap());
    }

    eprintln!("[sp1] downloaded {} to {:?}", download_url, build_dir.to_str().unwrap());
}

/// Download the file with a progress bar that indicates the progress.
#[cfg(any(feature = "network", feature = "network"))]
pub async fn download_file(
    client: &Client,
    url: &str,
    file: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> std::result::Result<(), String> {
    let res = client.get(url).send().await.or(Err(format!("Failed to GET from '{}'", &url)))?;

    let total_size =
        res.content_length().ok_or(format!("Failed to get content length from '{}'", &url))?;

    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})").unwrap()
        .progress_chars("#>-"));

    let mut downloaded: u64 = 0;
    let mut stream = res.bytes_stream();
    while let Some(item) = stream.next().await {
        let chunk = item.or(Err("Error while downloading file"))?;
        file.write_all(&chunk).await.or(Err("Error while writing to file"))?;
        let new = min(downloaded + (chunk.len() as u64), total_size);
        downloaded = new;
        pb.set_position(new);
    }
    pb.finish();

    Ok(())
}
