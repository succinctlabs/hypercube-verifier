#!/bin/bash

# Check the number of arguments
if [ $# -lt 2 ] || [ $# -gt 2 ]; then
    echo "Usage: $0 <s3_path> <simple|checkpoint|trace>"
    exit 1
fi

s3_path=$1
kind=$2

# Download files from S3
aws s3 cp s3://sp1-testing-suite/$s3_path/program.bin program.bin
aws s3 cp s3://sp1-testing-suite/$s3_path/stdin.bin stdin.bin

# Check for AVX-512 support
if lscpu | grep -q avx512; then
  # If AVX-512 is supported, add the specific features to RUSTFLAGS
  export RUSTFLAGS="-C opt-level=3 -C target-cpu=native -C target-feature=+avx512ifma,+avx512vl"
else
  # If AVX-512 is not supported, just set target-cpu=native
  export RUSTFLAGS="-Copt-level=3 -C target-cpu=native"
fi

# Set environment variables
export RUST_BACKTRACE=1
export RUST_LOG=info
export SP1_ALLOW_DEPRECATED_HOOKS=true

# Run sp1-perf
cargo +nightly run -p sp1-perf --bin sp1-perf-executor --features bigint-rug \
    -- --program program.bin --stdin stdin.bin --executor-mode $kind

# Uncomment to generate flamegraphs
# cargo flamegraph --root --bin sp1-perf-executor --profile profiling --features bigint-rug \
#     -c "record -e cycles -F 999 --call-graph dwarf" -- \
#     --program program.bin \
#     --stdin stdin.bin \
#     --executor-mode $kind

# Uncomment to generate samply
# cd ../../

# cargo build --bin sp1-perf-executor --profile profiling --features bigint-rug --

# samply record ./target/profiling/sp1-perf-executor \
#     --program crates/perf/program.bin \
#     --stdin crates/perf/stdin.bin \
#     --executor-mode $kind
