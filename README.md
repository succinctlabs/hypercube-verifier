# The SP1 Hypercube Verifier

This is the verifier code for the SP1 Hypercube proof system.

> [!CAUTION]
>
> As of May 20th, 2025, the SP1 Hypercube proof system is still a research prototype.
> Do not use this code in production.

To give it a whirl, run

```sh
cargo run -- --proof-dir <path-to-proof> --vk-dir <path-to-vk>.
```

To get started, you can run the command for the provided `proof.bin` and `vk.bin` files like so:

```sh
cargo run -- --proof-dir proof.bin --vk-dir vk.bin
```


SP1 Hypercube employs a novel protocol: the *jagged polynomial commitment scheme*, details on which
can be found in `jagged-polynomial-commitments.pdf`.
