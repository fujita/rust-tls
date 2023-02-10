// SPDX-License-Identifier: GPL-2.0
//
//! Rust TLS server sample.

use crate::buf::Buf;
use core::ffi::c_void;
use kernel::{bindings, c_str, error, net, prelude::*};

#[allow(dead_code)]
mod buf;
#[allow(dead_code)]
mod crypto;
#[allow(dead_code)]
mod tls;

const CERT: &[u8] = include_bytes!("certs/test.crt");
// The format in defined in RFC 5915
const PRIVKEY: &[u8] = include_bytes!("certs/test.key");
const PRIVKEY_LEN: usize = 32;
const PORT: u16 = 443;

module! {
    type: RustTlsSrv,
    name: "rust_tls_srv",
    author: "FUJITA Tomonori",
    description: "Rust TLS1.3 server sample",
    license: "GPL",
}

#[repr(transparent)]
struct CryptoInfoAesGcm128(bindings::tls12_crypto_info_aes_gcm_128);

impl CryptoInfoAesGcm128 {
    fn new(k: &[u8], i: &[u8], s: &[u8]) -> Self {
        let mut iv = [0; 8];
        let mut key = [0; 16];
        let mut salt = [0; 4];

        key.clone_from_slice(k);
        iv.clone_from_slice(i);
        salt.clone_from_slice(s);

        CryptoInfoAesGcm128(bindings::tls12_crypto_info_aes_gcm_128 {
            info: bindings::tls_crypto_info {
                version: 0x0304,
                cipher_type: bindings::TLS_CIPHER_AES_GCM_128 as u16,
            },
            iv,
            key,
            salt,
            rec_seq: [0; 8],
        })
    }
}

fn setup_ktls(socket: &mut net::Socket, ctx: &tls::Context) -> Result {
    let sock: *mut bindings::socket = socket.sock;

    let mut sockptr = bindings::sockptr_t::default();
    let mut b = Buf::new_with_capacity(4)?;
    b.put_slice(b"tls\0")?;
    sockptr.set_is_kernel(true);
    sockptr.__bindgen_anon_1.kernel = b.as_mut().as_mut_ptr().cast();

    error::to_result(unsafe {
        bindings::sock_common_setsockopt(
            sock,
            bindings::SOL_TCP as i32,
            bindings::TCP_ULP as i32,
            sockptr,
            4,
        )
    })?;

    let sockptr_len = core::mem::size_of::<bindings::tls12_crypto_info_aes_gcm_128>() as u32;
    let c = CryptoInfoAesGcm128::new(ctx.client_key(), ctx.client_iv(), ctx.client_salt());
    sockptr.__bindgen_anon_1.kernel =
        &c.0 as *const bindings::tls12_crypto_info_aes_gcm_128 as *mut c_void;

    error::to_result(unsafe {
        bindings::sock_common_setsockopt(
            sock,
            bindings::SOL_TLS as i32,
            bindings::TLS_RX as i32,
            sockptr,
            sockptr_len,
        )
    })?;

    let c = CryptoInfoAesGcm128::new(ctx.server_key(), ctx.server_iv(), ctx.server_salt());
    sockptr.__bindgen_anon_1.kernel =
        &c.0 as *const bindings::tls12_crypto_info_aes_gcm_128 as *mut c_void;

    error::to_result(unsafe {
        bindings::sock_common_setsockopt(
            sock,
            bindings::SOL_TLS as i32,
            bindings::TLS_TX as i32,
            sockptr,
            sockptr_len,
        )
    })
}

fn create_listen_socket() -> Result<net::Socket> {
    let mut sock = net::Socket::new(net::Family::Ip, net::SocketType::Stream, net::Protocol::Tcp)?;

    sock.bind(&net::SocketAddr::V4(net::SocketAddrV4::new(
        net::Ipv4Addr::new(0, 0, 0, 0),
        PORT,
    )))?;

    sock.listen(1)?;

    Ok(sock)
}

unsafe extern "C" fn handler(_: *mut core::ffi::c_void) -> i32 {
    let mut listen_sock = match create_listen_socket() {
        Ok(s) => s,
        Err(_) => {
            pr_info!("failed to create a socket");
            return 1;
        }
    };

    let mut buf = match Buf::new_with_capacity(4096) {
        Ok(buf) => buf,
        Err(_) => return -1,
    };

    while !unsafe { bindings::kthread_should_stop() } {
        if let Ok(mut client) = listen_sock.accept() {
            let cfg = match tls::ServerConfig::new(&PRIVKEY[7..7 + PRIVKEY_LEN], CERT) {
                Ok(cfg) => cfg,
                Err(_) => continue,
            };

            if let Ok(ctx) = tls::Server::negotiate(cfg, &mut client) {
                // setup kTLS
                if setup_ktls(&mut client, &ctx).is_err() {
                    pr_info!("failed to set up kTLS");
                    continue;
                }
            } else {
                pr_info!("failed to negotiate");
                continue;
            }

            if let Ok(r) = client.recvmsg(&mut [buf.as_mut()], net::MSG_WAITALL) {
                pr_info!("read {} bytes", r);
            }

            if let Ok(r) = client.sendmsg(&mut [b"hello world"]) {
                pr_info!("send {} bytes", r);
            }
            pr_info!("closed connection");
        }
    }
    0
}

struct RustTlsSrv {
    task: *mut bindings::task_struct,
}

unsafe impl Sync for RustTlsSrv {}

impl kernel::Module for RustTlsSrv {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        let key = PRIVKEY;
        if key[0] != 0x30
            || key[2] != 0x02
            || key[3] != 0x01
            || key[4] != 0x01
            || key[5] != 0x04
            || key[6] != 0x20
        {
            pr_info!("unexpected private key format");
            return Err(error::code::EINVAL);
        }

        let task = unsafe {
            let task = bindings::kthread_create_on_node(
                Some(handler),
                core::ptr::null_mut() as _,
                bindings::NUMA_NO_NODE,
                c_str!("rust_tls_srv").as_char_ptr(),
            );
            bindings::wake_up_process(task);
            task
        };

        Ok(Self { task })
    }
}

impl Drop for RustTlsSrv {
    fn drop(&mut self) {
        unsafe {
            bindings::kthread_stop(self.task);
        }
    }
}
