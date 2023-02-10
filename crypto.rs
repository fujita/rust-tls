// SPDX-License-Identifier: GPL-2.0

use kernel::bindings;
use kernel::error::{code, to_result, Result};
use kernel::prelude::*;

fn from_err_ptr<T>(ptr: *mut T) -> Result<*mut T> {
    let const_ptr: *const core::ffi::c_void = ptr.cast();
    if unsafe { bindings::IS_ERR(const_ptr) } {
        let err = unsafe { bindings::PTR_ERR(const_ptr) };
        return to_result(err as core::ffi::c_int).map(|_| ptr);
    }
    Ok(ptr)
}

///
pub(crate) struct Skcipher {
    ptr: *mut bindings::crypto_sync_skcipher,
}

impl Drop for Skcipher {
    fn drop(&mut self) {
        unsafe { bindings::crypto_free_sync_skcipher(self.ptr) }
    }
}

impl Skcipher {
    ///
    pub(crate) fn new(name: &'static CStr, t: u32, mask: u32) -> Result<Self> {
        let ptr = unsafe {
            from_err_ptr(bindings::crypto_alloc_sync_skcipher(
                name.as_char_ptr(),
                t,
                mask,
            ))
        }?;
        Ok(Skcipher { ptr })
    }

    ///
    pub(crate) fn setkey(&mut self, data: &[u8]) -> Result {
        to_result(unsafe {
            bindings::crypto_skcipher_setkey(
                &mut (*self.ptr).base,
                data.as_ptr(),
                data.len() as u32,
            )
        })
    }
}

///
pub(crate) struct SkcipherRequest {
    ///
    pub(crate) ptr: *mut bindings::skcipher_request,
}

impl SkcipherRequest {
    ///
    pub(crate) fn new(tfm: &Skcipher) -> Result<Self> {
        let ptr = unsafe {
            from_err_ptr(bindings::skcipher_request_alloc(
                &mut (*tfm.ptr).base,
                bindings::GFP_KERNEL,
            ))
        }?;
        unsafe {
            bindings::skcipher_request_set_tfm(ptr, &mut (*tfm.ptr).base);
            bindings::skcipher_request_set_callback(ptr, 0, None, core::ptr::null_mut());
        }
        Ok(SkcipherRequest { ptr })
    }

    ///
    pub(crate) fn encrypt(&mut self) -> Result {
        to_result(unsafe { bindings::crypto_skcipher_encrypt(self.ptr) })
    }
}

impl Drop for SkcipherRequest {
    fn drop(&mut self) {
        unsafe {
            bindings::skcipher_request_zero(self.ptr);
            bindings::skcipher_request_free(self.ptr);
        }
    }
}

///
pub(crate) struct Aead {
    ///
    pub(crate) ptr: *mut bindings::crypto_aead,
}

impl Aead {
    ///
    pub(crate) fn new(name: &'static CStr, t: u32, mask: u32) -> Result<Self> {
        let ptr =
            unsafe { from_err_ptr(bindings::crypto_alloc_aead(name.as_char_ptr(), t, mask)) }?;
        Ok(Aead { ptr })
    }
}

impl Drop for Aead {
    fn drop(&mut self) {
        unsafe { bindings::crypto_free_aead(self.ptr) }
    }
}

///
pub(crate) struct Kpp {
    ///
    pub(crate) ptr: *mut bindings::crypto_kpp,
}

impl Kpp {
    ///
    pub(crate) fn new(name: &'static CStr, t: u32, mask: u32) -> Result<Self> {
        let ptr = unsafe { from_err_ptr(bindings::crypto_alloc_kpp(name.as_char_ptr(), t, mask)) }?;
        Ok(Kpp { ptr })
    }
}

impl Drop for Kpp {
    fn drop(&mut self) {
        unsafe { bindings::crypto_free_kpp(self.ptr) }
    }
}

///
pub(crate) struct Akcipher {
    ///
    pub(crate) ptr: *mut bindings::crypto_akcipher,
}

impl Akcipher {
    ///
    pub(crate) fn new(name: &'static CStr, t: u32, mask: u32) -> Result<Self> {
        let ptr =
            unsafe { from_err_ptr(bindings::crypto_alloc_akcipher(name.as_char_ptr(), t, mask)) }?;
        Ok(Akcipher { ptr })
    }
}

impl Drop for Akcipher {
    fn drop(&mut self) {
        unsafe { bindings::crypto_free_akcipher(self.ptr) }
    }
}

///
pub(crate) struct AkcipherRequest {
    ///
    pub(crate) ptr: *mut bindings::akcipher_request,
}

impl AkcipherRequest {
    ///
    pub(crate) fn new(tfm: &Akcipher) -> Result<Self> {
        let ptr = unsafe { bindings::akcipher_request_alloc(tfm.ptr, bindings::GFP_KERNEL) };
        if ptr.is_null() {
            Err(code::ENOMEM)
        } else {
            Ok(AkcipherRequest { ptr: ptr })
        }
    }
}

pub(crate) fn get_random_bytes(buf: &mut [u8]) -> Result {
    let r = unsafe {
        to_result(bindings::crypto_get_default_rng())?;
        let r = bindings::crypto_rng_get_bytes(
            bindings::crypto_default_rng,
            buf.as_mut_ptr(),
            buf.len() as u32,
        );
        bindings::crypto_put_default_rng();
        r
    };
    to_result(r)
}
