use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, GenericParam};

/// Derive macro for generating `Into<Shape<ExprRef<F>, ExprExtRef<EF>>>` implementations.
///
/// This macro generates an implementation that converts a struct into a Shape::Struct variant,
/// including all fields that have a `Word` type or are the generic type parameter itself.
///
/// # Example
/// ```compile_fail
/// #[derive(IntoShape)]
/// struct AddOperation<T> {
///     value: Word<T>,
/// }
/// ```
///
/// Will generate:
/// ```compile_fail
/// impl<F: Field, EF: ExtensionField<F>> Into<Shape<ExprRef<F>, ExprExtRef<EF>>>
///     for AddOperation<ExprRef<F>>
/// {
///     fn into(self) -> Shape<ExprRef<F>, ExprExtRef<EF>> {
///         Shape::Struct(
///             "AddOperation".to_string(),
///             vec![("value".to_string(), Box::new(self.value.into()))],
///         )
///     }
/// }
/// ```
pub fn into_shape_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;
    let name_str = name.to_string();

    // Check that we have exactly one generic type parameter
    let generics = &ast.generics;
    if generics.params.len() != 1 {
        panic!("IntoShape requires exactly one generic type parameter");
    }

    let _type_param = match &generics.params[0] {
        GenericParam::Type(ty) => &ty.ident,
        _ => panic!("IntoShape requires the generic parameter to be a type parameter"),
    };

    // Extract fields from the struct
    let fields = match &ast.data {
        Data::Struct(data_struct) => {
            let field_impls = data_struct
                .fields
                .iter()
                .filter_map(|field| {
                    let field_name = field.ident.as_ref()?;
                    let field_name_str = field_name.to_string();

                    // Include all fields
                    Some(quote! {
                        (#field_name_str.to_string(), Box::new(self.#field_name.into()))
                    })
                })
                .collect::<Vec<_>>();
            field_impls
        }
        _ => panic!("IntoShape can only be derived for structs"),
    };

    // Generate the implementation
    let expanded = quote! {
        impl<F: slop_algebra::Field, EF: slop_algebra::ExtensionField<F>> Into<sp1_hypercube::ir::Shape<sp1_hypercube::ir::ExprRef<F>, sp1_hypercube::ir::ExprExtRef<EF>>>
            for #name<sp1_hypercube::ir::ExprRef<F>>
        {
            fn into(self) -> sp1_hypercube::ir::Shape<sp1_hypercube::ir::ExprRef<F>, sp1_hypercube::ir::ExprExtRef<EF>> {
                sp1_hypercube::ir::Shape::Struct(
                    #name_str.to_string(),
                    vec![
                        #(#fields,)*
                    ],
                )
            }
        }
    };

    TokenStream::from(expanded)
}
