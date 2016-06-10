# Implementation of cryptographic functionalities

- Arcfour
- MD5, SHA-1, SHA-2, SHA-3

## Usage

```
$ cd crypt-impl-rust/examples
$ cargo build
$ dmesg | ./target/debug/arcfour foo | ./target/debug/arcfour foo
$ dmesg | ./target/debug/md5sum
$ dmesg | ./target/debug/sha1sum
$ dmesg | ./target/debug/sha224sum
$ dmesg | ./target/debug/sha256sum
$ dmesg | ./target/debug/sha384sum
$ dmesg | ./target/debug/sha512sum
$ dmesg | ./target/debug/sha3sum-224
$ dmesg | ./target/debug/sha3sum-256
$ dmesg | ./target/debug/sha3sum-384
$ dmesg | ./target/debug/sha3sum-512
```
