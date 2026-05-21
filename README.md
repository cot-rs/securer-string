# Securer String

[![crates.io](https://img.shields.io/crates/v/securer-string?logo=rust)](https://crates.io/crates/securer-string)
[![crates.io](https://img.shields.io/crates/d/securer-string)](https://crates.io/crates/securer-string)
[![API Docs](https://docs.rs/securer-string/badge.svg)](https://docs.rs/securer-string/)

A [Rust] library that implements a data type (wrapper around `Vec<u8>` and other types) suitable for storing sensitive information such as passwords and private keys in memory.

Featuring:

- Supports various secure datatypes: `SecureVec`, `SecureBytes`, `SecureArray`, `SecureString`, `SecureBox`
- automatically zeroing out in the destructor using [zeroize]
- `mlock` and `madvise` protection if possible
- formatting as `***SECRET***` to prevent leaking into logs
- (optionally) de/serializable into anything [serde] supports as a byte string

[Rust]: https://www.rust-lang.org
[zeroize]: https://crates.io/crates/zeroize
[serde]: https://serde.rs/

## Usage

```rust
use securer_string::*;

let pw = SecureString::from("correct horse battery staple");

// Compared in constant time:
// (Obviously, you should store hashes in real apps, not plaintext passwords)
let are_pws_equal = pw == SecureString::from("correct horse battery staple".to_string()); // true

// Formatting, printing without leaking secrets into logs
let text_to_print = format!("{}", SecureString::from("hello")); // "***SECRET***"

// Clearing memory
// THIS IS DONE AUTOMATICALLY IN THE DESTRUCTOR
// (but you can force it)
let mut my_sec = SecureString::from("hello");
my_sec.zero_out();
// (It also sets the length to 0)
assert_eq!(my_sec.unsecure(), "");
```

Be careful with `SecureString::from`: if you have a borrowed string, it will be copied.
Use `SecureString::new` if you have a `Vec<u8>`.


## Contributors

<a href="https://github.com/cot-rs/securer-string/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=cot-rs/securer-string" />
</a>

Made with [contrib.rocks](https://contrib.rocks).

## Acknowledgments

This crate was forked from [`secure-string`](https://crates.io/crates/secure-string), which was based on [`secstr`](https://crates.io/crates/secstr).

## License

securer-string is licensed under either of the following, at your option:

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
* MIT License ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in Cot by you shall be
dual licensed under the MIT License and Apache License, Version 2.0, without any additional terms or conditions.
