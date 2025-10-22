use slop_alloc::{Backend, CpuBackend};

use crate::{Tensor, TensorViewMut};

/// A backend that supports the 2D transpose operation.
///
/// The operation assumes the input tensor is a 2D tensor with the last two dimensions being the
/// dimensions to be transposed.
pub trait TransposeBackend<T>: Backend {
    /// Transposes the input tensor into the output tensor.
    fn transpose_tensor_into(src: &Tensor<T, Self>, dst: TensorViewMut<T, Self>);
}

impl<T, A: TransposeBackend<T>> Tensor<T, A> {
    /// Returns a new tensor with the last two dimensions transposed.
    ///
    /// This function panics if the input tensor is not a 2D tensor.
    pub fn transpose(&self) -> Tensor<T, A> {
        let mut sizes = self.sizes().to_vec();
        let len = sizes.len();
        assert_eq!(len, 2, "Transpose is only supported for 2D tensors");
        sizes.swap(len - 1, len - 2);
        let mut dst = Tensor::with_sizes_in(sizes, self.backend().clone());

        unsafe {
            dst.assume_init();
        }
        A::transpose_tensor_into(self, dst.as_view_mut());

        dst
    }
}

impl<T: Copy> TransposeBackend<T> for CpuBackend {
    fn transpose_tensor_into(src: &Tensor<T, Self>, dst: TensorViewMut<T, Self>) {
        // Dimension checks.
        debug_assert_eq!(src.sizes().len(), 2);
        debug_assert_eq!(dst.sizes().len(), 2);
        debug_assert_eq!(src.sizes()[src.sizes().len() - 1], dst.sizes()[dst.sizes().len() - 2]);
        debug_assert_eq!(src.sizes()[src.sizes().len() - 2], dst.sizes()[dst.sizes().len() - 1]);

        // Transpose the data.
        let input_width = src.sizes()[src.sizes().len() - 1];
        let input_height = src.sizes()[src.sizes().len() - 2];

        transpose::transpose(src.as_buffer(), dst.as_mut_slice(), input_width, input_height);
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;

    #[test]
    fn test_transpose() {
        let mut rng = rand::thread_rng();

        for (width, height) in [(2, 3), (5, 10), (100, 500), (1000, 1 << 16)] {
            let tensor =
                Tensor::<u32>::from((0..width * height).map(|_| rng.gen()).collect::<Vec<_>>())
                    .reshape([height, width]);

            let transposed = tensor.transpose();
            assert_eq!(transposed.sizes(), &[width, height]);

            let i = rng.gen_range(0..height);
            let j = rng.gen_range(0..width);
            assert_eq!(tensor[[i, j]], transposed[[j, i]]);
        }
    }
}
