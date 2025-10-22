# SP1 Testing Suite

## Prerequisites

- [GitHub CLI](https://cli.github.com/)

## Run the testing suite

Set the workloads you want to run in the `workflow.sh` file. The workloads are keys in the
`sp1-testing-suite` s3 bucket.

```sh
CPU_WORKLOADS=("fibonacci-17k" "ssz-withdrawals")
CUDA_WORKLOADS=()
NETWORK_WORKLOADS=()
```

Run the workflow.

```sh
./workflow.sh
```

## Test the executor

Set the workloads you want to run in the `workflow_executor.sh` file. The workloads are keys in the
`sp1-testing-suite` s3 bucket.

```sh
SIMPLE_WORKLOADS=("fibonacci-17k" "ssz-withdrawals")
CHECKPOINT_WORKLOADS=()
TRACE_WORKLOADS=()
```

Run the workflow.

```sh
./workflow_executor.sh
```

## `run_s3.sh`

This script will run the `sp1-perf` binary on a workload in the `sp1-testing-suite` s3 bucket.

### Example Usage

The following command will run the `fibonacci-17k` workload and generate a proof using the CPU prover.

```sh
./run_s3.sh fibonacci-17k cpu
```

## `run_executor.sh`

This script will run the `sp1-perf-executor` binary on a workload in the `sp1-testing-suite` s3 bucket.

### `run_executor.sh` Example Usage

The following command will run the `fibonacci-17k` workload in checkpoint mode.

```sh
./run_executor.sh fibonacci-17k checkpoint
```

If you want, install [`cargo-flamegraph`](https://github.com/flamegraph-rs/flamegraph) and uncomment
these lines to generate flamegraphs for profiling executor performance.

```sh
cargo flamegraph --root --bin sp1-perf-executor --profile profiling --features bigint-rug \
    -c "record -e cycles -F 999 --call-graph dwarf" -- \
    --program program.bin \
    --stdin stdin.bin \
    --executor-mode $kind
```

If you're on Mac, it can be easier to use samply instead.

```sh
cd ../../

cargo build --bin sp1-perf-executor --profile profiling --features bigint-rug --

samply record ./target/profiling/sp1-perf-executor \
    --program crates/perf/program.bin \
    --stdin crates/perf/stdin.bin \
    --executor-mode $kind
```

## View the results of a testing suite run

Visit the [actions](https://github.com/succinctlabs/sp1/actions) tab on GitHub to view the results.

## Uploading new workloads

Take any existing binary that uses `sp1-sdk` and run it with `SP1_DUMP=1`. This will dump the
program and stdin to the current directory.

```sh
SP1_DUMP=1 cargo run --release
aws s3 cp program.bin s3://sp1-testing-suite/<workload>/program.bin
aws s3 cp stdin.bin s3://sp1-testing-suite/<workload>/stdin.bin
```
