#![cfg(test)]
use std::sync::Arc;

use sp1_core_machine::{riscv::RiscvAir, utils::setup_logger};
use sp1_hypercube::prover::{DefaultTraceGenerator, ProverSemaphore, TraceGenerator};
use sp1_primitives::SP1Field;
use sp1_prover::{
    recursion::RECURSION_MAX_LOG_ROW_COUNT,
    shapes::{
        build_shape_from_recursion_air_event_count, create_test_shape, max_count,
        SP1RecursionProofShape, DEFAULT_ARITY,
    },
    CompressAir, SP1ProverBuilder,
};
use sp1_recursion_executor::{shape::RecursionShape, RecursionAirEventCount};

#[tokio::test]
async fn find_recursion_shape() {
    setup_logger();
    let elf = test_artifacts::FIBONACCI_ELF;
    let prover = SP1ProverBuilder::new().without_recursion_vks().build().await;
    let (_, _, vk) = prover.core().setup(&elf).await;

    let machine = RiscvAir::<SP1Field>::machine();
    let chip_clusters = &machine.shape().chip_clusters;

    // Find the recursion proof shape that fits the normalize programs verifying all core shards.
    let mut max_cluster_count = RecursionAirEventCount::default();

    for cluster in chip_clusters {
        let shape = create_test_shape(cluster);
        let program = sp1_prover::recursion::normalize_program_from_input(
            &prover.recursion().recursive_core_verifier,
            &shape.dummy_input(vk.clone()),
        );
        max_cluster_count = max_count(max_cluster_count, program.event_counts);
    }

    // Iterate on this shape until the compose program verifying DEFAULT_ARITY proofs of shape
    // `current_shape` can be proved using `current_shape`.
    let mut current_shape = build_shape_from_recursion_air_event_count(&max_cluster_count);
    let trace_generator = DefaultTraceGenerator::new(CompressAir::<SP1Field>::compress_machine());
    loop {
        // Create DEFAULT_ARITY dummy proofs of shape `current_shape`
        let input = prover.recursion().dummy_reduce_input_with_shape(DEFAULT_ARITY, &current_shape);
        // Compile the program that verifies those `DEFAULT_ARITY` proofs.
        let program = prover.recursion().compose_program_from_input(&input);
        let setup_permits = ProverSemaphore::new(1);
        let program = Arc::new(program);
        // The preprocessed traces contain the information of the minimum required table heights
        // to prove the compose program.
        let preprocessed_traces = trace_generator
            .generate_preprocessed_traces(program, RECURSION_MAX_LOG_ROW_COUNT, setup_permits)
            .await;

        // Check if the `current_shape` heights are insufficient.
        let updated_key_values = preprocessed_traces
            .preprocessed_traces
            .into_iter()
            .filter_map(|(chip, trace)| {
                let real_height = trace.num_real_entries();
                let expected_height = current_shape.shape.height_of_name(&chip).unwrap();

                if real_height > expected_height {
                    tracing::warn!(
                        "Insufficient height for chip {}: expected {}, got {}",
                        chip,
                        expected_height,
                        real_height
                    );
                    if chip == "PublicValues" {
                        Some((chip, real_height))
                    } else {
                        Some((chip, real_height.next_multiple_of(32)))
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // If no need to update the chip heights, `current_shape` is good enough.
        if updated_key_values.is_empty() {
            break;
        }
        // Otherwise, update the heights in `current_shape` and repeat the loop.
        for (chip, real_height) in updated_key_values {
            current_shape.shape.insert_with_name(&chip, real_height);
        }
    }

    // Write the shape to a file.
    let shape = SP1RecursionProofShape {
        shape: RecursionShape::new(
            current_shape
                .shape
                .into_iter()
                .map(|(chip, height)| {
                    let new_height =
                        if chip == "PublicValues" { height } else { height.next_multiple_of(32) };
                    (chip, new_height)
                })
                .collect(),
        ),
    };

    let mut file = std::fs::File::create("compress_shape.json").unwrap();
    serde_json::to_writer_pretty(&mut file, &shape).unwrap();
}
