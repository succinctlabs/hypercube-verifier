use std::{path::PathBuf, sync::Arc};

use clap::Parser;
use sp1_core_machine::utils::setup_logger;
use sp1_prover::{
    components::CpuSP1ProverComponents,
    shapes::{build_vk_map_to_file, DEFAULT_ARITY},
    SP1ProverBuilder,
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    build_dir: PathBuf,
    #[clap(short, long)]
    start: Option<usize>,
    #[clap(short, long)]
    end: Option<usize>,
}
#[tokio::main]
async fn main() {
    setup_logger();
    let args = Args::parse();

    let maximum_compose_arity = DEFAULT_ARITY;
    let build_dir = args.build_dir;
    let num_compiler_workers = 1;
    let num_setup_workers = 1;
    let start = args.start;
    let end = args.end;

    let prover = Arc::new(SP1ProverBuilder::new().build().await);

    build_vk_map_to_file::<CpuSP1ProverComponents>(
        build_dir.clone(),
        maximum_compose_arity,
        false,
        num_compiler_workers,
        num_setup_workers,
        start.and_then(|s| end.map(|e| (s..e).collect())),
        prover,
    )
    .await
    .unwrap();
}
