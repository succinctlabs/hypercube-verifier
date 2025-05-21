use hypercube_alloc::{Buffer, CpuBackend};
use hypercube_tensor::{Dimensions, Tensor};
use p3_field::{AbstractExtensionField, AbstractField};
use rayon::prelude::*;
use std::sync::{Arc, Mutex};

use crate::{partial_lagrange_blocking, Point};

pub(crate) fn eval_mle_at_point_blocking<
    F: AbstractField + Sync,
    EF: AbstractExtensionField<F> + Send + Sync,
>(
    mle: &Tensor<F, CpuBackend>,
    point: &Point<EF, CpuBackend>,
) -> Tensor<EF, CpuBackend> {
    let partial_lagrange = partial_lagrange_blocking(point);
    let mut sizes = mle.sizes().to_vec();
    sizes.remove(0);
    let dimensions = Dimensions::try_from(sizes).unwrap();
    let total_len = dimensions.total_len();
    
    // Pre-allocation of the result buffer
    let result = Arc::new(Mutex::new(vec![EF::zero(); total_len]));
    
    // Process in parallel using Rayon
    mle.as_buffer()
        .par_chunks_exact(mle.strides()[0])
        .zip(partial_lagrange.as_buffer().par_iter())
        .for_each(|(chunk, scalar)| {
            // Process each chunk with a thread-local accumulator
            let mut local_result = vec![EF::zero(); total_len];
            
            // Avoid allocation in the inner loop
            for (i, a) in chunk.iter().enumerate() {
                if i < total_len {
                    // Compute scalar * a directly into the accumulator
                    local_result[i] = scalar.clone() * a.clone();
                }
            }
            
            // Update the global result with our local computation
            let result_clone = Arc::clone(&result);
            let mut global_result = result_clone.lock().unwrap();
            for i in 0..total_len {
                global_result[i] += local_result[i].clone();
            }
        });

    // Create the final tensor
    let result_buffer = Buffer::from(Arc::try_unwrap(result).unwrap().into_inner().unwrap());
    Tensor { storage: result_buffer, dimensions }
}

// Add a specialized implementation for the case when the number of polynomials is small
pub(crate) fn eval_mle_at_point_small_batch<
    F: AbstractField + Sync,
    EF: AbstractExtensionField<F> + Send + Sync,
>(
    mle: &Tensor<F, CpuBackend>,
    point: &Point<EF, CpuBackend>,
) -> Tensor<EF, CpuBackend> {
    // For small batches (fewer than 4 polynomials), use a different approach
    // that avoids the overhead of parallelization
    let partial_lagrange = partial_lagrange_blocking(point);
    let mut sizes = mle.sizes().to_vec();
    sizes.remove(0);
    let dimensions = Dimensions::try_from(sizes).unwrap();
    let total_len = dimensions.total_len();
    
    // Direct computation without parallelization for small batches
    let mut result = vec![EF::zero(); total_len];
    
    for (chunk, scalar) in mle.as_buffer()
        .chunks_exact(mle.strides()[0])
        .zip(partial_lagrange.as_buffer().iter())
    {
        for (i, a) in chunk.iter().enumerate() {
            if i < total_len {
                result[i] += scalar.clone() * a.clone();
            }
        }
    }
    
    let result_buffer = Buffer::from(result);
    Tensor { storage: result_buffer, dimensions }
}