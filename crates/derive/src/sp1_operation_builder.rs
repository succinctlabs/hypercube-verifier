use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

/// Derive macro for generating `SP1OperationBuilder` implementation.
///
/// This macro generates a verbatim implementation of `SP1OperationBuilder` following
/// the pattern used in AddOperation, with the struct name replaced accordingly.
///
/// # Requirements
/// - The struct must have no or exactly one type parameter. If the type parameter has constraints,
///   then this constraint must be satisfiable by [sp1_hypercube::ir::ConstraintCompiler].
/// - The associated Input type must implement `Clone`, `params_vec()`, and `to_input()`. The later
///   two can be obtained by deriving [crate::InputParams] and [crate::InputExpr], respectively.
/// - The associated Output type must implement `SP1OperationOutput`.
///
/// # Example
/// ```compile_fail
/// #[derive(SP1OperationBuilder)]
/// pub struct AddOperation<T> {
///     pub value: Word<T>,
/// }
/// ```
///
/// generates:
/// ```compile_fail
/// impl SP1OperationBuilder<AddOperation<<ConstraintCompiler as AirBuilder>::F>>
///     for ConstraintCompiler
/// {
///     fn eval_operation(
///         &mut self,
///         input: <AddOperation<<ConstraintCompiler as AirBuilder>::F> as SP1Operation<
///             ConstraintCompiler
///         >>::Input,
///     ) -> <AddOperation<<ConstraintCompiler as AirBuilder>::F> as SP1Operation<
///             ConstraintCompiler
///     >>::Output{
///         type F = <ConstraintCompiler as AirBuilder>::F;
///         type O = <AddOperation<<ConstraintCompiler as AirBuilder>::F> as SP1Operation<
///             ConstraintCompiler,
///         >>::Output;
///
///         let result: O = O::alloc();
///         GLOBAL_AST.lock().unwrap().call_operation(
///             "AddOperation".to_string(),
///             input.clone().params_vec(),
///             result.into(),
///         );
///
///         // Record the operation module
///         if !self.modules().contains_key("AddOperation") {
///             let mut ctx = FuncCtx::new();
///             let func_input = input.to_input(&mut ctx);
///             let func_output: O = result.to_output(&mut ctx);
///
///             self.register_module(
///                 "AddOperation".to_string(),
///                 func_input.clone().params_vec(),
///                 |body| {
///                     let output: O = AddOperation::<F>::lower(body, func_input);
///                     func_output.assign(output);
///                     output.into()
///                 },
///             );
///         }
///         result
///     }
/// }
/// ```
pub fn sp1_operation_builder_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;
    let name_str = name.to_string();

    // Check that we have either zero or one type parameter
    if ast.generics.params.len() > 1 {
        panic!("SP1OperationBuilder requires at most one type parameter");
    }

    // Generate the struct type based on whether it has type parameters
    let struct_type = if ast.generics.params.is_empty() {
        quote! { #name }
    } else {
        quote! { #name<<sp1_hypercube::ir::ConstraintCompiler as slop_air::AirBuilder>::F> }
    };

    // Generate the implementation
    let expanded = quote! {
        impl crate::air::SP1OperationBuilder<#struct_type>
            for sp1_hypercube::ir::ConstraintCompiler
        {
            fn eval_operation(
                &mut self,
                input: <#struct_type as crate::air::SP1Operation<
                    sp1_hypercube::ir::ConstraintCompiler
                >>::Input,
            ) -> <#struct_type as crate::air::SP1Operation<
                sp1_hypercube::ir::ConstraintCompiler
            >>::Output{
                type F = <sp1_hypercube::ir::ConstraintCompiler as slop_air::AirBuilder>::F;
                type O = <#struct_type as crate::air::SP1Operation<
                    sp1_hypercube::ir::ConstraintCompiler,
                >>::Output;

                let result : O = <O as sp1_hypercube::ir::SP1OperationOutput<O>>::alloc();
                sp1_hypercube::ir::GLOBAL_AST.lock().unwrap().call_operation(
                    #name_str.to_string(),
                    input.clone().params_vec(),
                    result.into(),
                );

                // Record the operation module
                if !self.modules().contains_key(#name_str) {
                    let mut ctx = sp1_hypercube::ir::FuncCtx::new();
                    let func_input = input.to_input(&mut ctx);
                    let func_output : O = <O as sp1_hypercube::ir::SP1OperationOutput<O>>::to_output(&result, &mut ctx);

                    self.register_module(
                        // sp1_hypercube::ir::FuncDecl::new(
                            #name_str.to_string(),
                            func_input.clone().params_vec(),
                            // result.into(),
                        // ),
                        |body| {
                            let output : O = <#struct_type as crate::air::SP1Operation<sp1_hypercube::ir::ConstraintCompiler>>::lower(body, func_input);
                            <O as sp1_hypercube::ir::SP1OperationOutput<O>>::assign(&func_output, output);
                            output.into()
                        },
                    );
                }
                result
            }
        }
    };

    TokenStream::from(expanded)
}
