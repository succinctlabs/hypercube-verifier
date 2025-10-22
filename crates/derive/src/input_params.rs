use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, Attribute, Data, DeriveInput, GenericParam, Ident, TypeParamBound};

/// Derive macro for generating a `params_vec` function that returns a vector of tuples
/// containing field names and their values with `.into()` called on them.
///
/// # Example
/// ```compile_fail
/// #[derive(InputParams)]
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
///     fn params_vec(
///         &self,
///     ) -> Vec<(
///         String,
///         Shape<
///             ExprRef<<ConstraintCompiler as AirBuilder>::F>,
///             ExprExtRef<<ConstraintCompiler as ExtensionBuilder>::EF>,
///         >,
///     )> {
///         vec![
///             ("a".to_string(), self.a.into()),
///             ("b".to_string(), self.b.into()),
///             ("cols".to_string(), self.cols.into()),
///             ("is_real".to_string(), self.is_real.into()),
///         ]
///     }
/// }
/// ```
pub fn input_params_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;

    // Extract fields from the struct
    let (fields, field_entries) = match &ast.data {
        Data::Struct(data_struct) => data_struct
            .fields
            .iter()
            .filter_map(|field| {
                let field_name = field.ident.as_ref()?;
                let field_name_str = field_name.to_string();

                // Parse attributes from the field
                let attribute = parse_picus_attributes(&field.attrs);

                Some((
                    field.clone(),
                    quote! {
                        (#field_name_str.to_string(), #attribute, self.#field_name.into())
                    },
                ))
            })
            .unzip::<_, _, Vec<_>, Vec<_>>(),
        _ => panic!("InputParams can only be derived for structs"),
    };

    let field_names = fields
        .iter()
        .map(|field| field.ident.clone().expect("Field should be named."))
        .collect::<Vec<_>>();

    // Check if the first type parameter has SP1AirBuilder bound
    let first_param_name = match ast.generics.params.first() {
        Some(GenericParam::Type(ty)) => Some(&ty.ident),
        _ => None,
    };

    let has_sp1_air_builder = ast.generics.params.first().is_some_and(|param| {
        if let GenericParam::Type(type_param) = param {
            type_param.bounds.iter().any(|bound| {
                if let TypeParamBound::Trait(trait_bound) = bound {
                    trait_bound.path.segments.iter().any(|seg| seg.ident == "SP1AirBuilder")
                } else {
                    false
                }
            })
        } else {
            false
        }
    });

    // Generate the implementation
    let expanded = if has_sp1_air_builder {
        let num_params = ast.generics.params.len();
        let first_param_name = first_param_name.expect("First type parameter should be named.");

        // Replace all the instances of the first type parameter with `A`
        let field_type_params = fields
            .iter()
            .map(|field| {
                let name = field.ident.as_ref().expect("Field should be named.").clone();
                let ty_of = &field.ty;
                quote! { #name: #ty_of }
            })
            .collect::<Vec<_>>();

        if num_params == 1 {
            // Case 1: Single type parameter with SP1AirBuilder constraint
            quote! {
                impl<#first_param_name: SP1AirBuilder> #name<#first_param_name> {
                    #[allow(clippy::too_many_arguments)]
                    pub const fn new(#(#field_type_params),*) -> Self {
                        Self {
                            #(#field_names),*
                        }
                    }
                }

                impl #name<sp1_hypercube::ir::ConstraintCompiler> {
                    fn params_vec(
                        self,
                    ) -> Vec<(
                        String,
                        sp1_hypercube::ir::Attribute,
                        sp1_hypercube::ir::Shape<
                            <sp1_hypercube::ir::ConstraintCompiler as slop_air::AirBuilder>::Expr,
                            <sp1_hypercube::ir::ConstraintCompiler as slop_air::ExtensionBuilder>::ExprEF,
                        >,
                    )> {
                        vec![
                            #(#field_entries,)*
                        ]
                    }
                }
            }
        } else {
            // Case 2: Multiple type parameters, first one has SP1AirBuilder constraint
            // Extract the remaining type parameters and substitute AB:: with <ConstraintCompiler as
            let remaining_params_with_constraint_compiler = replace_bounds(
                ast.generics.params.iter().skip(1),
                first_param_name.clone(),
                "< sp1_hypercube :: ir :: ConstraintCompiler as slop_air :: AirBuilder >",
            );

            let remaining_params = ast.generics.params.iter().skip(1);

            let type_args = ast.generics.params.iter().skip(1).filter_map(|param| {
                if let GenericParam::Type(type_param) = param {
                    let ident = &type_param.ident;
                    Some(quote! { #ident })
                } else {
                    None
                }
            });

            let type_args_clone = type_args.clone();
            quote! {
                impl<#first_param_name: SP1AirBuilder, #(#remaining_params),*> #name<#first_param_name, #(#type_args_clone),*> {
                    #[allow(clippy::too_many_arguments)]
                    pub const fn new(#(#field_type_params),*) -> Self {
                        Self {
                            #(#field_names),*
                        }
                    }
                }

                impl<#(#remaining_params_with_constraint_compiler),*> #name<sp1_hypercube::ir::ConstraintCompiler, #(#type_args),*> {
                    fn params_vec(
                        self,
                    ) -> Vec<(
                        String,
                        sp1_hypercube::ir::Attribute,
                        sp1_hypercube::ir::Shape<
                            <sp1_hypercube::ir::ConstraintCompiler as slop_air::AirBuilder>::Expr,
                            <sp1_hypercube::ir::ConstraintCompiler as slop_air::ExtensionBuilder>::ExprEF,
                        >,
                    )> {
                        vec![
                            #(#field_entries,)*
                        ]
                    }
                }
            }
        }
    } else {
        panic!("InputParams requires the first type parameter to have SP1AirBuilder bound");
    };

    TokenStream::from(expanded)
}

fn replace_bounds<'a, I>(bounds: I, target: Ident, replacement: &'a str) -> Vec<TokenStream2>
where
    I: Iterator<Item = &'a GenericParam>,
{
    bounds
        .map(move |bound| {
            if let GenericParam::Type(type_param) = bound {
                let ident = &type_param.ident;
                let bounds = &type_param.bounds;

                let bounds_str: String = quote! { #bounds }.to_string();
                let target_pattern = format!("{target}");
                let new_bounds_str = bounds_str.replace(&target_pattern, replacement);

                let new_bounds =
                    syn::parse_str::<syn::TypeParam>(&format!("{ident}: {new_bounds_str}"))
                        .unwrap_or_else(|_| type_param.clone());

                quote! { #new_bounds }
            } else {
                quote! { #bound }
            }
        })
        .collect()
}

/// Parse SP1 attributes from field attributes
fn parse_picus_attributes(attrs: &[Attribute]) -> TokenStream2 {
    for attr in attrs {
        if attr.path.is_ident("picus") {
            // Parse the meta inside the attribute
            if let Ok(syn::Meta::List(meta_list)) = attr.parse_meta() {
                // Check if the list contains the identifier "input" or "output"
                for nested in meta_list.nested {
                    if let syn::NestedMeta::Meta(syn::Meta::Path(path)) = nested {
                        if path.is_ident("input") {
                            return quote! {
                                sp1_hypercube::ir::Attribute {
                                    picus: sp1_hypercube::ir::PicusArg::Input,
                                }
                            };
                        } else if path.is_ident("output") {
                            return quote! {
                                sp1_hypercube::ir::Attribute {
                                    picus: sp1_hypercube::ir::PicusArg::Output,
                                }
                            };
                        }
                    }
                }
            }
        }
    }
    // Default to Unknown if no attribute is specified
    quote! { sp1_hypercube::ir::Attribute::default() }
}
