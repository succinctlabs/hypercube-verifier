mod air;

pub use air::*;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sp1_core_executor::Program;
    use test_artifacts::U256XU2048_MUL_ELF;

    use crate::{
        io::SP1Stdin,
        utils::{self, run_test},
    };

    #[tokio::test]
    async fn test_u256xu2048_mul() {
        utils::setup_logger();
        let program = Arc::new(Program::from(&U256XU2048_MUL_ELF).unwrap());
        run_test(program, SP1Stdin::new()).await.unwrap();
    }
}
