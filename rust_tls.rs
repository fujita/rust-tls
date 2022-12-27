// SPDX-License-Identifier: GPL-2.0
//
//! Rust TLS experiment.

use alloc::boxed::Box;
use core::pin::Pin;
use kernel::bindings;
use kernel::prelude::*;
use kernel::str;
use kernel::Result;

mod buf;
mod quic;
#[allow(dead_code)]
mod tls;

module! {
    type: RustTls,
    name: "rust_tls",
    author: "FUJITA Tomonori",
    description: "Rust TLS1.3 experiment",
    license: "GPL",
}

struct RustTls {
    proto: Pin<Box<bindings::proto>>,
    protosw: Pin<Box<bindings::inet_protosw>>,
}
unsafe impl Send for RustTls {}
unsafe impl Sync for RustTls {}

impl kernel::Module for RustTls {
    fn init(_name: &'static CStr, _module: &'static ThisModule) -> Result<Self> {
        let mut proto = Pin::from(Box::try_new(quic::build_proto())?);
        let mut protosw = Pin::from(Box::try_new(quic::build_protosw())?);

        unsafe {
            //proto.as_mut().owner = _module;
            protosw.as_mut().prot = &mut *proto.as_mut();
            let r = bindings::proto_register(&mut *proto.as_mut(), 1);
            pr_info!("proto_register {}", r);

            bindings::inet_register_protosw(&mut *protosw.as_mut());

            let mut socket = core::ptr::null_mut();

            let r = bindings::sock_create_kern(
                &mut bindings::init_net,
                bindings::PF_INET as _,
                bindings::sock_type_SOCK_STREAM as _,
                quic::IPPROTO_QUIC as _,
                &mut socket,
            );
            pr_info!("create socket {}", r);

            let mut addr = bindings::sockaddr_in::default();
            addr.sin_family = bindings::AF_INET as u16;
            addr.sin_port = 4433_u16.to_be();

            let r = bindings::kernel_bind(
                socket,
                &mut addr as *mut bindings::sockaddr_in as *mut bindings::sockaddr,
                core::mem::size_of::<bindings::sockaddr>() as _,
            );
            pr_info!("bind socket {}", r);
        }

        Ok(RustTls { proto, protosw })
    }
}

impl Drop for RustTls {
    fn drop(&mut self) {
        unsafe {
            bindings::inet_unregister_protosw(&mut *self.protosw.as_mut());
            bindings::proto_unregister(&mut *self.proto.as_mut());
        }
    }
}
