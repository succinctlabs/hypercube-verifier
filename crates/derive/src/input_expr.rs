use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, GenericParam, Type, TypeParamBound};

/// Derive macro for generating `to_input` and `to_output` functions that create struct instances
/// with fields populated using `Expr::input_*` or `Expr::output_*` functions respectively.
///
/// This macro requires the struct to have exactly one type parameter with SP1AirBuilder constraint.
///
/// Rules for both functions:
/// 1. If the field type is `AB::Expr` or `AB::Var`, use `Expr::input_arg(ctx)` /
///    `Expr::output_arg(ctx)`
/// 2. If the field type is an array, use `core::array::from_fn(|_| Expr::input_arg(ctx))` /
///    `core::array::from_fn(|_| Expr::output_arg(ctx))`
/// 3. Otherwise, use `Expr::input_from_struct(ctx)` / `Expr::output_from_struct(ctx)`
///
/// # Example
/// ```compile_fail
/// #[derive(InputExpr)]
/// pub struct AddOperationInput<AB: SP1AirBuilder> {
///     pub a: Word<AB::Expr>,
///     pub b: Word<AB::Expr>,
///     pub cols: AddOperation<AB::Var>,
///     pub is_real: AB::Expr,
/// }
/// ```
///
/// Will generate:
/// ```compile_fail
/// impl AddOperationInput<ConstraintCompiler> {
///     fn to_input(&self, ctx: &mut FuncCtx) -> AddOperationInput<ConstraintCompiler> {
///         AddOperationInput::new(
///             Expr::input_from_struct(ctx), // a is Word<AB::Expr>
///             Expr::input_from_struct(ctx), // b is Word<AB::Expr>
///             Expr::input_from_struct(ctx), // cols is AddOperation<AB::Var>
///             Expr::input_arg(ctx),         // is_real is AB::Expr
///         )
///     }
/// }
/// ```
pub fn input_expr_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;

    // Check that we have at least one type parameter
    if ast.generics.params.is_empty() {
        panic!("InputExpr requires at least one type parameter");
    }

    // Check that the type parameter has SP1AirBuilder bound
    let first_param_name = match &ast.generics.params[0] {
        GenericParam::Type(ty) => &ty.ident,
        _ => panic!("InputExpr requires a type parameter"),
    };

    let has_sp1_air_builder = match &ast.generics.params[0] {
        GenericParam::Type(type_param) => type_param.bounds.iter().any(|bound| {
            if let TypeParamBound::Trait(trait_bound) = bound {
                trait_bound.path.segments.iter().any(|seg| seg.ident == "SP1AirBuilder")
            } else {
                false
            }
        }),
        _ => false,
    };

    if !has_sp1_air_builder {
        panic!("InputExpr requires the first type parameter to have SP1AirBuilder bound");
    }

    // Analyze additional type parameters
    let mut type_param_replacements = Vec::new();
    for (i, param) in ast.generics.params.iter().enumerate() {
        if i == 0 {
            // First parameter is always ConstraintCompiler
            if let GenericParam::Type(ty) = param {
                type_param_replacements
                    .push((ty.ident.clone(), quote! { sp1_hypercube::ir::ConstraintCompiler }));
            }
        } else {
            // Check if it has Into<AB::Expr> bound, if so we replace it with `<ConstraintCompiler
            // as Airbuilder>::Expr`
            if let GenericParam::Type(type_param) = param {
                let has_into_expr = type_param.bounds.iter().any(|bound| {
                    if let TypeParamBound::Trait(trait_bound) = bound {
                        // Check if it's Into<AB::Expr>
                        if trait_bound.path.segments.len() == 1
                            && trait_bound.path.segments[0].ident == "Into"
                        {
                            // Check the generic argument
                            if let syn::PathArguments::AngleBracketed(args) =
                                &trait_bound.path.segments[0].arguments
                            {
                                if args.args.len() == 1 {
                                    if let syn::GenericArgument::Type(Type::Path(type_path)) =
                                        &args.args[0]
                                    {
                                        if type_path.path.segments.len() == 2
                                            && type_path.path.segments[0].ident == *first_param_name
                                            && type_path.path.segments[1].ident == "Expr"
                                        {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    false
                });

                if has_into_expr {
                    type_param_replacements.push((
                        type_param.ident.clone(),
                        quote! { <sp1_hypercube::ir::ConstraintCompiler as slop_air::AirBuilder>::Expr },
                    ));
                } else {
                    panic!(
                        "Type parameter {} must have bound 'Into<{}::Expr>'",
                        type_param.ident, first_param_name
                    );
                }
            }
        }
    }

    // Extract field names and determine which Expr function to use for both input and output
    let (field_names, input_exprs, output_exprs): (Vec<_>, Vec<_>, Vec<_>) = match &ast.data {
        Data::Struct(data_struct) => {
            let items: Vec<_> = data_struct
                .fields
                .iter()
                .filter_map(|field| {
                    let field_name = field.ident.as_ref()?;

                    // Check if field is an array
                    let (input_expr, output_expr) = if let Type::Array(_array_type) = &field.ty {
                        // For arrays, use core::array::from_fn
                        (
                            quote! { core::array::from_fn(|_| <sp1_hypercube::ir::ConstraintCompiler as slop_air::AirBuilder>::Expr::input_arg(ctx)) },
                            quote! { core::array::from_fn(|_| <sp1_hypercube::ir::ConstraintCompiler as slop_air::AirBuilder>::Expr::output_arg(ctx)) }
                        )
                    } else if let Type::Path(type_path) = &field.ty {
                        // Check if the field type is AB::Expr or AB::Var
                        if type_path.path.segments.len() == 2 {
                            let first_seg = &type_path.path.segments[0];
                            let second_seg = &type_path.path.segments[1];
                            if first_seg.ident == *first_param_name && (second_seg.ident == "Expr" || second_seg.ident == "Var") {
                                (
                                    quote! { <sp1_hypercube::ir::ConstraintCompiler as slop_air::AirBuilder>::Expr::input_arg(ctx) },
                                    quote! { <sp1_hypercube::ir::ConstraintCompiler as slop_air::AirBuilder>::Expr::output_arg(ctx) }
                                )
                            } else {
                                (
                                    quote! { <sp1_hypercube::ir::ConstraintCompiler as slop_air::AirBuilder>::Expr::input_from_struct(ctx) },
                                    quote! { <sp1_hypercube::ir::ConstraintCompiler as slop_air::AirBuilder>::Expr::output_from_struct(ctx) }
                                )
                            }
                        } else {
                            (
                                quote! { <sp1_hypercube::ir::ConstraintCompiler as slop_air::AirBuilder>::Expr::input_from_struct(ctx) },
                                quote! { <sp1_hypercube::ir::ConstraintCompiler as slop_air::AirBuilder>::Expr::output_from_struct(ctx) }
                            )
                        }
                    } else {
                        (
                            quote! { <sp1_hypercube::ir::ConstraintCompiler as slop_air::AirBuilder>::Expr::input_from_struct(ctx) },
                            quote! { <sp1_hypercube::ir::ConstraintCompiler as slop_air::AirBuilder>::Expr::output_from_struct(ctx) }
                        )
                    };

                    Some((field_name.clone(), input_expr, output_expr))
                })
                .collect();

            let mut names = Vec::new();
            let mut inputs = Vec::new();
            let mut outputs = Vec::new();
            for (n, i, o) in items {
                names.push(n);
                inputs.push(i);
                outputs.push(o);
            }
            (names, inputs, outputs)
        }
        _ => panic!("InputExpr can only be derived for structs"),
    };

    // Check if there's a 'new' constructor by looking at field count
    let input_constructor_call = if field_names.is_empty() {
        quote! { #name::new() }
    } else {
        quote! { #name::new(#(#input_exprs),*) }
    };

    let output_constructor_call = if field_names.is_empty() {
        quote! { #name::new() }
    } else {
        quote! { #name::new(#(#output_exprs),*) }
    };

    // Generate the concrete type parameters for the impl
    let concrete_types: Vec<_> = type_param_replacements.iter().map(|(_, ty)| ty).collect();

    // Generate the implementation
    let expanded = quote! {
        impl #name<#(#concrete_types),*> {
            fn to_input(&self, ctx: &mut sp1_hypercube::ir::FuncCtx) -> #name<#(#concrete_types),*> {
                #input_constructor_call
            }

            fn to_output(&self, ctx: &mut sp1_hypercube::ir::FuncCtx) -> #name<#(#concrete_types),*> {
                #output_constructor_call
            }
        }
    };

    TokenStream::from(expanded)
}
