---
description: Implement SP1Operation for an operation to enable constraint compiler support
---

# Implement SP1Operation for $ARGUMENTS

This guide explains how to implement `SP1Operation` for an operation in the SP1 codebase so that the constraint compiler can capture and process calls to that operation.

## Current Implementation Status

Check if the operation already has SP1Operation implemented:
!`rg -l "impl.*SP1Operation.*$ARGUMENTS" crates/core/machine/src/operations/ || echo "No SP1Operation implementation found for $ARGUMENTS"`

## Overview

The SP1 constraint compiler needs to intercept operation calls to generate appropriate constraints. This is achieved through the `SP1Operation` trait and proper usage patterns in Air implementations.

## Example Implementations in the Codebase

Here are existing implementations you can reference:

### Simple Operations
- **AddOperation**: @crates/core/machine/src/operations/add.rs - Look for the `SP1OperationInput` derive and `impl SP1Operation`
- **SubOperation**: @crates/core/machine/src/operations/sub.rs - Similar structure to AddOperation
- **U16CompareOperation**: @crates/core/machine/src/operations/u16_compare.rs - Shows the complete pattern

### Complex Operations with Trait Bounds
- **BitwiseU16Operation**: @crates/core/machine/src/operations/bitwise_u16.rs - Shows how to handle operations that use other operations internally with trait bounds
- **LtOperationUnsigned**: @crates/core/machine/src/operations/slt.rs - Example with nested operations

### Usage in Air Implementations
- **AddChip**: @crates/core/machine/src/alu/add_sub/add.rs - Look for `SP1Operation::eval` in the `impl Air` block
- **DivRemChip**: @crates/core/machine/src/alu/divrem/mod.rs - Example of using `LtOperationUnsigned` via `SP1Operation::eval`
- **MemoryGlobalChip**: @crates/core/machine/src/memory/global.rs - Another example of using `LtOperationUnsigned`

### Constraint Compiler Implementations
- **SP1CoreOperationBuilder trait**: @crates/core/machine/src/air/operation.rs - Contains the trait definition and implementation
- **Constraint compiler AST types**: @crates/core/compiler/src/ir/ast.rs - Look for the `Ty` enum and its Display implementation
- **Constraint compiler builders**: @crates/core/compiler/src/ir/builder.rs - Contains `SP1OperationBuilder` implementations for various operations:
  - Look for `impl SP1OperationBuilder<AddOperation<F>>`
  - Look for `impl SP1OperationBuilder<SubOperation<F>>`
  - Look for `impl SP1OperationBuilder<BitwiseU16Operation<F>>`
  - Look for `impl SP1OperationBuilder<U16CompareOperation<F>>`
  - Look for `impl SP1OperationBuilder<LtOperationUnsigned<F>>`

## Step-by-Step Implementation Guide

### Important: Run Cargo Check Frequently!

Throughout this implementation, you should run `cargo check` at key checkpoints (marked with 🔍) to catch errors early:
- After implementing the operation trait (Step 3)
- After updating SP1CoreOperationBuilder (Step 4)
- After constraint compiler changes (Step 5)
- After updating all call sites (Step 7)

This helps identify issues before they compound into harder-to-debug problems.

### Step 1: Create the Input Struct

For an operation `XOperation` with an evaluation method like:
```rust
pub fn eval_x<AB: SP1AirBuilder>(
    builder: &mut AB,
    param1: AB::Expr,
    param2: Word<AB::Expr>,
    cols: XOperation<AB::Var>,
    is_real: AB::Expr,
) {
    // operation implementation
}
```

Create a corresponding input struct with **exactly matching parameter names and types**:

```rust
#[derive(SP1OperationInput)]
pub struct XOperationInput<AB: SP1AirBuilder> {
    pub param1: AB::Expr,
    pub param2: Word<AB::Expr>,
    pub cols: XOperation<AB::Var>,
    pub is_real: AB::Expr,
}

impl<AB: SP1AirBuilder> XOperationInput<AB> {
    pub fn new(
        param1: AB::Expr,
        param2: Word<AB::Expr>,
        cols: XOperation<AB::Var>,
        is_real: AB::Expr,
    ) -> Self {
        Self { param1, param2, cols, is_real }
    }
}
```

**Important**: The field names must match the parameter names exactly!

### Step 2: Implement SP1Operation Trait

```rust
impl<AB: SP1AirBuilder> SP1Operation<AB> for XOperation<AB::F> {
    type Input = XOperationInput<AB>;
    type Output = (); // or whatever the eval method returns

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        Self::eval_x(builder, input.param1, input.param2, input.cols, input.is_real)
    }
}
```

### Step 3: Add Required Derives to the Operation Struct

Ensure your operation struct has the necessary derives:

```rust
#[derive(AlignedBorrow, Default, Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct XOperation<T> {
    // fields
}
```

**🔍 CHECKPOINT**: Run `cargo check -p sp1-core-machine` to verify your operation compiles correctly before proceeding.

### Step 4: Update SP1CoreOperationBuilder Trait

Add your operation to both the trait definition and its implementation in @crates/core/machine/src/air/operation.rs:

```rust
pub trait SP1CoreOperationBuilder:
    SP1AirBuilder
    + SP1OperationBuilder<AddOperation<F<Self>>>
    // ... other operations ...
    + SP1OperationBuilder<XOperation<F<Self>>>  // Add this line
{
}

impl<AB> SP1CoreOperationBuilder for AB where
    AB: SP1AirBuilder
        + SP1OperationBuilder<AddOperation<F<Self>>>
        // ... other operations ...
        + SP1OperationBuilder<XOperation<F<Self>>>  // Add this line
{
}
```

**🔍 CHECKPOINT**: Run `cargo check -p sp1-core-machine` to ensure the trait bounds are correct.

### Step 5: Update the Constraint Compiler

The constraint compiler needs to recognize your operation. In @crates/core/compiler/src/ir/:

#### 5.1. Update @crates/core/compiler/src/ir/ast.rs

Add imports:
```rust
use sp1_core_machine::{
    // ... other imports ...
    operations::{
        // ... other operations ...
        XOperation, // Add your operation
    },
};
```

Add to the `Ty` enum:
```rust
pub enum Ty<Expr, ExprExt> {
    // ... other variants ...
    XOperation(XOperation<Expr>),
}
```

Add Display implementation:
```rust
impl<Expr, ExprExt> Display for Ty<Expr, ExprExt>
where
    Expr: Debug + Display,
    ExprExt: Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // ... other cases ...
            Ty::XOperation(x_operation) => write!(f, "{x_operation:?}"),
        }
    }
}
```

Add to `to_lean_type()` implementation:
```rust
impl<Expr, ExprExt> Ty<Expr, ExprExt> {
    pub fn to_lean_type(&self) -> String {
        match self {
            // ... other cases ...
            Ty::XOperation(_) => "XOperation".to_string(),
            // ... rest of cases ...
            _ => unimplemented!(),
        }
    }
}
```

Add an AST method:
```rust
impl<F: Field, EF: ExtensionField<F>> Ast<ExprRef<F>, ExprExtRef<EF>> {
    // ... other methods ...
    
    pub fn x_operation(
        &mut self,
        param1: ExprRef<F>,
        param2: Word<ExprRef<F>>,
        cols: XOperation<ExprRef<F>>,
        is_real: ExprRef<F>,
    ) {
        let func = FuncDecl::new(
            "XOperation",
            vec![
                Ty::Expr(param1),
                Ty::Word(param2),
                Ty::XOperation(cols),
                Ty::Expr(is_real),
            ],
            vec![], // or output types if the operation returns something
        );
        let op = OpExpr::Call(func);
        self.operations.push(op);
    }
}
```

#### 5.2. Update @crates/core/compiler/src/ir/builder.rs

Add imports:
```rust
use sp1_core_machine::{
    // ... other imports ...
    operations::{
        // ... other operations ...
        XOperation, XOperationInput,
    },
};
```

Implement SP1OperationBuilder:
```rust
impl SP1OperationBuilder<XOperation<F>> for ConstraintCompiler {
    fn eval_operation(
        &mut self,
        input: <XOperation<F> as SP1Operation<Self>>::Input,
    ) -> <XOperation<F> as SP1Operation<Self>>::Output {
        GLOBAL_AST.lock().unwrap().x_operation(
            input.param1,
            input.param2,
            input.cols,
            input.is_real,
        );

        if !self.modules.contains_key("XOperation") {
            let mut ctx = FuncCtx::new();
            let input_param1 = Expr::input_arg(&mut ctx);
            let input_param2 = Word([Expr::input_arg(&mut ctx), Expr::input_arg(&mut ctx)]);
            let input_cols = Expr::input_from_struct::<XOperation<Expr>>(&mut ctx);
            let input_is_real = Expr::input_arg(&mut ctx);

            let func_input = XOperationInput::<Self>::new(
                input_param1,
                input_param2,
                input_cols,
                input_is_real,
            );

            self.register_module(
                FuncDecl::with_parameter_names(
                    "XOperation",
                    vec![
                        Ty::Expr(input_param1),
                        Ty::Word(input_param2),
                        Ty::XOperation(input_cols),
                        Ty::Expr(input_is_real),
                    ],
                    vec![],
                    XOperationInput::<Self>::PARAMETER_NAMES,
                ),
                |body| {
                    XOperation::<F>::lower(body, func_input);
                },
            );
        }
    }
}
```

### Step 6: Update ALL Call Sites to Use SP1Operation::eval

**CRITICAL**: To ensure the constraint compiler can capture operation calls, ALL uses of operations need to cast to `SP1Operation::eval`, not just in Air implementations!

#### Update Calls Everywhere

✅ **DO** update calls in Air implementations (chips):
```rust
impl<AB> Air<AB> for SomeChip
where
    AB: SP1CoreAirBuilder,  // Use SP1CoreAirBuilder for chips/airs
{
    fn eval(&self, builder: &mut AB) {
        // Instead of:
        // XOperation::<AB::F>::eval_x(builder, param1, param2, cols, is_real);
        
        // Use:
        <XOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            XOperationInput::<AB>::new(param1, param2, cols, is_real),
        );
    }
}
```

✅ **DO** update calls in operation implementations that use other operations:
```rust
impl<F: Field> SomeOtherOperation<F> {
    pub fn eval_some_other<AB>(builder: &mut AB, ...) 
    where
        AB: SP1AirBuilder + SP1OperationBuilder<XOperation<<AB as AirBuilder>::F>>,
    {
        // Instead of:
        // XOperation::<AB::F>::eval_x(builder, param1, param2, cols, is_real);
        
        // Use:
        <XOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            XOperationInput::<AB>::new(param1, param2, cols, is_real),
        );
    }
}
```

#### Important Notes on Trait Bounds

1. **For Chips/Airs**: Use `SP1CoreAirBuilder` instead of manually specifying trait bounds
2. **For Operations**: Add specific `SP1OperationBuilder` bounds for each operation used
3. **Avoid trait recursion**: Operations should NOT use `SP1CoreAirBuilder`

#### Example: Operation Using Another Operation

Here's how `LtOperationUnsigned` uses `U16CompareOperation`:

```rust
// In the operation's eval method
impl<F: Field> LtOperationUnsigned<F> {
    pub fn eval_lt_unsigned<AB>(
        builder: &mut AB,
        b: Word<AB::Expr>,
        c: Word<AB::Expr>,
        cols: LtOperationUnsigned<AB::Var>,
        is_real: AB::Expr,
    )
    where
        AB: SP1AirBuilder + SP1OperationBuilder<U16CompareOperation<<AB as AirBuilder>::F>>,
    {
        // Use SP1Operation::eval for the nested operation
        <U16CompareOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            U16CompareOperationInput::<AB>::new(
                b_comp_limb.into(),
                c_comp_limb.into(),
                cols.u16_compare_operation,
                is_real.clone(),
            ),
        );
    }
}

// In the SP1Operation implementation
impl<AB> SP1Operation<AB> for LtOperationUnsigned<AB::F>
where
    AB: SP1AirBuilder + SP1OperationBuilder<U16CompareOperation<<AB as AirBuilder>::F>>,
{
    type Input = LtOperationUnsignedInput<AB>;
    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        Self::eval_lt_unsigned(builder, input.b, input.c, input.cols, input.is_real);
    }
}
```

#### Handling Complex Trait Bounds

If your operation uses other operations internally (like `BitwiseU16Operation` uses `U16toU8OperationUnsafe`), you'll need to add trait bounds:

```rust
impl<AB> SP1Operation<AB> for XOperation<AB::F>
where
    AB: SP1AirBuilder 
        + SP1OperationBuilder<SomeOtherOperation<<AB as AirBuilder>::F>>,
{
    // implementation
}
```

### Step 7: Update Call Sites and Verify

**🔍 CHECKPOINT**: After updating call sites, run both:
```bash
cargo check -p sp1-core-machine
cargo check -p sp1-constraint-compiler
```

This final check ensures:
- All trait bounds are correctly propagated
- All call sites have been updated
- The constraint compiler can process your operation

## Common Pitfalls and Solutions

### 1. Missing Serialize/Deserialize Derives
If you get errors about `Serialize` or `Deserialize` not being implemented:
- Add `serde::{Deserialize, Serialize}` to imports
- Add these derives to your operation struct and any nested structs
- Check nested operations too (e.g., if using `U16MSBOperation` inside your operation)

### 2. Trait Bound Cycles
If you get cycle errors when adding trait bounds:
- Use `<AB as AirBuilder>::F` instead of `AB::F` in trait bounds
- For chips/airs, use `SP1CoreAirBuilder` instead of manual trait bounds
- For operations, only add the specific `SP1OperationBuilder` bounds you need

### 3. Understanding When to Update Calls
**ALL operation calls need to use `SP1Operation::eval` for constraint compiler interception:**
- ✅ In Air implementations (chips)
- ✅ In operation implementations that call other operations
- ✅ Anywhere an operation is used

### 4. Parameter Name Mismatches
The input struct fields MUST match the exact parameter names from the eval method. This is enforced by the `SP1OperationInput` derive macro.

### 5. Complex Trait Bound Errors
When you see errors like "trait bound `AB: TrivialOperationBuilder` is not satisfied":
- For chip implementations: Change `AB: SP1AirBuilder` to `AB: SP1CoreAirBuilder`
- For operation implementations: Add missing `SP1OperationBuilder` bounds
- Look for transitive dependencies (if A uses B, and B uses C, A might need bounds for C)

### 6. Finding All Call Sites
To find all places where an operation is used:
```bash
# Find direct method calls
rg "XOperation::eval_x" crates/core/machine/src/

# Find struct usage  
rg "XOperation<" crates/core/machine/src/
```

### 7. Missing to_lean_type() Implementation
If you're implementing constraint compiler support, don't forget to add the `to_lean_type()` case:
- The `to_lean_type()` method in `ast.rs` is used for Lean code generation
- Without it, the constraint compiler will panic with `unimplemented!()` when generating Lean code
- The type name should match the operation name (e.g., `"XOperation".to_string()`)

## Complete Example: U16CompareOperation

Here's a complete example showing all the steps:

1. **Original operation** (@crates/core/machine/src/operations/u16_compare.rs):
```rust
pub fn eval_compare_u16<AB: SP1AirBuilder>(
    builder: &mut AB,
    a: AB::Expr,
    b: AB::Expr,
    cols: U16CompareOperation<AB::Var>,
    is_real: AB::Expr,
) { /* ... */ }
```

2. **Input struct and SP1Operation impl**:
```rust
#[derive(SP1OperationInput)]
pub struct U16CompareOperationInput<AB: SP1AirBuilder> {
    pub a: AB::Expr,
    pub b: AB::Expr,
    pub cols: U16CompareOperation<AB::Var>,
    pub is_real: AB::Expr,
}

impl<AB: SP1AirBuilder> SP1Operation<AB> for U16CompareOperation<AB::F> {
    type Input = U16CompareOperationInput<AB>;
    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        Self::eval_compare_u16(builder, input.a, input.b, input.cols, input.is_real);
    }
}
```

3. **Usage in Air implementation**:
```rust
// In some chip's eval method:
<U16CompareOperation<AB::F> as SP1Operation<AB>>::eval(
    builder,
    U16CompareOperationInput::<AB>::new(a, b, cols, is_real),
);
```

This ensures the constraint compiler can intercept and process the operation calls correctly.

## Quick Reference

### For a New Operation `XOperation`

1. **Add to operation file**:
   ```rust
   #[derive(SP1OperationInput)]
   pub struct XOperationInput<AB: SP1AirBuilder> { /* match eval params exactly */ }
   
   impl<AB: SP1AirBuilder> SP1Operation<AB> for XOperation<AB::F> {
       type Input = XOperationInput<AB>;
       type Output = ();
       fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
           Self::eval_x(builder, /* destructure input */);
       }
   }
   ```

2. **Add to** @crates/core/machine/src/air/operation.rs:
   ```rust
   + SP1OperationBuilder<XOperation<F<Self>>>
   ```

3. **Add to** @crates/core/compiler/src/ir/ast.rs:
   - Import: `XOperation`
   - Ty enum: `XOperation(XOperation<Expr>)`
   - Display impl: `Ty::XOperation(x) => write!(f, "{x:?}")`
   - to_lean_type impl: `Ty::XOperation(_) => "XOperation".to_string()`
   - AST method: `pub fn x_operation(...)`

4. **Add to** @crates/core/compiler/src/ir/builder.rs:
   - Import: `XOperation, XOperationInput`
   - Implement `SP1OperationBuilder<XOperation<F>>`

5. **Update all call sites** to use `SP1Operation::eval`

### Common Commands

```bash
# Check compilation
cargo check -p sp1-core-machine -p sp1-constraint-compiler

# Find operation usage
rg "XOperation::" crates/core/machine/src/

# Find where operation is defined
rg -l "struct XOperation" crates/core/machine/src/operations/
```

## Verification

After implementation:
!`cargo check -p sp1-core-machine -p sp1-constraint-compiler 2>&1 | head -20`