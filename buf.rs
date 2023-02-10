// SPDX-License-Identifier: GPL-2.0

use kernel::error;
use kernel::prelude::*;

pub(crate) struct Buf {
    vec: Vec<u8>,
    pos: usize,
}

impl Buf {
    pub(crate) fn new_with_capacity(len: usize) -> Result<Self> {
        let mut vec = Vec::try_with_capacity(len)?;
        vec.try_resize(len, 0)?;
        Ok(Buf { vec, pos: 0 })
    }

    pub(crate) fn resize(&mut self, len: usize) -> Result {
        self.vec.try_resize(len, 0).map_err(|_| error::code::ENOMEM)
    }

    pub(crate) fn get_pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn set_pos(&mut self, pos: usize) {
        self.pos = pos
    }

    pub(crate) fn get_u8(&mut self) -> Result<u8> {
        const LEN: usize = core::mem::size_of::<u8>();
        let mut buf = [0u8; LEN];
        self.get_slice(&mut buf)?;
        Ok(buf[0])
    }

    pub(crate) fn put_u8(&mut self, val: u8) -> Result {
        let buf = [val];
        self.put_slice(&buf)
    }

    pub(crate) fn get_u16_be(&mut self) -> Result<u16> {
        const LEN: usize = core::mem::size_of::<u16>();
        let mut buf = [0u8; LEN];
        self.get_slice(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    pub(crate) fn put_u16_be(&mut self, val: u16) -> Result {
        self.put_slice(&val.to_be_bytes())
    }

    pub(crate) fn get_u32_be(&mut self) -> Result<u32> {
        const LEN: usize = core::mem::size_of::<u32>();
        let mut buf = [0u8; LEN];
        self.get_slice(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    pub(crate) fn put_u32_be(&mut self, val: u32) -> Result {
        self.put_slice(&val.to_be_bytes())
    }

    pub(crate) fn get_u24_be(&mut self) -> Result<u32> {
        const LEN: usize = core::mem::size_of::<u32>();
        let mut buf = [0u8; LEN];
        self.get_slice(&mut buf[1..])?;
        Ok(u32::from_be_bytes(buf))
    }

    pub(crate) fn put_u24_be(&mut self, val: u32) -> Result {
        self.put_slice(&val.to_be_bytes()[1..])
    }

    pub(crate) fn get_u64_be(&mut self) -> Result<u64> {
        const LEN: usize = core::mem::size_of::<u64>();
        let mut buf = [0u8; LEN];
        self.get_slice(&mut buf)?;
        Ok(u64::from_be_bytes(buf))
    }

    pub(crate) fn put_u64_be(&mut self, val: u64) -> Result {
        self.put_slice(&val.to_be_bytes())
    }

    pub(crate) fn get_slice(&mut self, dst: &mut [u8]) -> Result {
        let len = dst.len();
        if self.get_pos() + len <= self.vec.len() {
            (&mut dst[0..len]).copy_from_slice(&self.vec.as_mut_slice()[self.pos..self.pos + len]);
            self.pos += len;
            Ok(())
        } else {
            Err(error::code::EIO)
        }
    }

    pub(crate) fn put_slice(&mut self, src: &[u8]) -> Result {
        if self.vec.len() >= self.get_pos() + src.len() {
            self.vec.as_mut_slice()[self.pos..self.pos + src.len()].copy_from_slice(src);
            self.pos += src.len();
            Ok(())
        } else {
            Err(error::code::EIO)
        }
    }
}

impl AsRef<[u8]> for Buf {
    fn as_ref(&self) -> &[u8] {
        self.vec.as_slice()
    }
}

impl AsMut<[u8]> for Buf {
    fn as_mut(&mut self) -> &mut [u8] {
        self.vec.as_mut_slice()
    }
}
