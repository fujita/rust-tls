# Rust in-kernel TLS handshake

This experiment is for figuring out how well Rust could work for in-kernel TLS 1.3 handshake.

There is [some debate](https://lwn.net/Articles/896746/) over in-kernel TLS handshake mainly because of the complexity. Rust could help auditing the complicated security-relevant code.

This can establish a QUIC connection with [Quinn's example client](https://github.com/quinn-rs/quinn), Rust QUIC implementation. Only minimum server side functionality and connection establishment are supported for now.

I'll work on Rust crypto support for mainline. Meanwhile you can compile this kernel module with [my fork of Linux kernel](https://github.com/fujita/linux/tree/rust-tls).

```bash
$ make KDIR=~/git/linux LLVM=1
```
