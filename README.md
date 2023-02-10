# Rust in-kernel TLS handshake

This experiment is for figuring out how well Rust could work for in-kernel TLS 1.3 handshake.

There is [some debate](https://lwn.net/Articles/896746/) over in-kernel TLS handshake mainly because of the complexity. Rust could help auditing the complicated security-relevant code.

This module works as a simple TLS1.3 server. Once a handshake is done, [in-kernel TLS support](https://docs.kernel.org/networking/tls-offload.html) is set up to read and write some bytes.

Building
--------
The X.509 certificate and key (DER format) are embeded into the module. Only ECC certificate (prime256v1 and sha256) is supported for now. You can use files in [`certs` directory](certs/).

I'll work on Rust abstractions for mainline. Meanwhile you can compile this kernel module with [my fork of Linux kernel](https://github.com/fujita/linux/tree/rust-tls).
