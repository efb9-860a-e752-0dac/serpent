# Serpent

A pure Rust implementation of the Serpent block cipher candidate for the AES standard.

## Warnings

This crate does not promise any form of implementation guarantees for timing or space characteristics. It's a naive translation of the reference C code from the [Serpent](https://www.cl.cam.ac.uk/~rja14/serpent.html) authors.

The intent of this crate is to provide a pure implementation of the cipher for non-critical applications. It handles the known-answer test vectors from the reference submission for variable keys, variable text, and the input table that is designed to exercise the S-boxes. Use it where you need to encrypt and decrypt weird payloads and would rather do it from Rust than C, but _please_ don't use it anywhere sensitive.

It's using external crates and definitely uses the `std`, if you're looking for something that needs to run `no_std` on some dinky little embedded device, it would need some massage to get rid of the nice things from the Rust std.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.