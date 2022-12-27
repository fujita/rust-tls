use kernel::error;
use kernel::Result;

pub(crate) struct Buf<'a> {
    ptr: &'a mut [u8],
    idx: usize,
}

impl<'a> Buf<'a> {
    pub(crate) fn new(ptr: &'a mut [u8]) -> Self {
        Buf { ptr, idx: 0 }
    }

    pub(crate) fn get_index(&self) -> usize {
        self.idx
    }

    pub(crate) fn set_index(&mut self, idx: usize) {
        self.idx = idx
    }

    pub(crate) fn get_u8(&mut self) -> Result<u8> {
        if self.idx + 1 <= self.ptr.len() {
            let v = self.ptr[self.idx];
            self.idx += 1;
            Ok(v)
        } else {
            Err(error::code::EIO)
        }
    }

    pub(crate) fn put_u8(&mut self, val: u8) -> Result {
        if self.idx + 1 <= self.ptr.len() {
            self.ptr[self.idx] = val;
            self.idx += 1;
            Ok(())
        } else {
            Err(error::code::EIO)
        }
    }

    pub(crate) fn get_u16_be(&mut self) -> Result<u16> {
        const LEN: usize = core::mem::size_of::<u16>();
        if self.idx + LEN <= self.ptr.len() {
            let mut buf = [0; LEN];
            buf.copy_from_slice(&self.ptr[self.idx..self.idx + LEN]);
            let v = u16::from_be_bytes(buf);
            self.idx += LEN;
            Ok(v)
        } else {
            Err(error::code::EIO)
        }
    }

    pub(crate) fn put_u16_be(&mut self, val: u16) -> Result {
        const LEN: usize = core::mem::size_of::<u16>();
        if self.idx + LEN <= self.ptr.len() {
            let v = val.to_be_bytes();
            for i in 0..LEN {
                self.put_u8(v[i])?;
            }
            Ok(())
        } else {
            Err(error::code::EIO)
        }
    }

    pub(crate) fn get_u32_be(&mut self) -> Result<u32> {
        const LEN: usize = core::mem::size_of::<u32>();
        if self.idx + LEN <= self.ptr.len() {
            let mut buf = [0; LEN];
            buf.copy_from_slice(&self.ptr[self.idx..self.idx + LEN]);
            let v = u32::from_be_bytes(buf);
            self.idx += LEN;
            Ok(v)
        } else {
            Err(error::code::EIO)
        }
    }

    pub(crate) fn put_u32_be(&mut self, val: u32) -> Result {
        const LEN: usize = core::mem::size_of::<u32>();
        if self.idx + LEN <= self.ptr.len() {
            let v = val.to_be_bytes();
            for i in 0..LEN {
                self.put_u8(v[i])?;
            }
            Ok(())
        } else {
            Err(error::code::EIO)
        }
    }

    pub(crate) fn get_u24_be(&mut self) -> Result<u32> {
        const LEN: usize = core::mem::size_of::<u32>() - 1;
        if self.idx + LEN <= self.ptr.len() {
            let mut buf = [0; LEN + 1];
            buf[1..].copy_from_slice(&self.ptr[self.idx..self.idx + LEN]);
            let v = u32::from_be_bytes(buf);
            self.idx += LEN;
            Ok(v)
        } else {
            Err(error::code::EIO)
        }
    }

    pub(crate) fn put_u24_be(&mut self, val: u32) -> Result {
        const LEN: usize = core::mem::size_of::<u32>() - 1;
        if self.idx + LEN <= self.ptr.len() {
            let v = val.to_be_bytes();
            for i in 0..LEN {
                self.put_u8(v[1 + i])?;
            }
            Ok(())
        } else {
            Err(error::code::EIO)
        }
    }

    pub(crate) fn put_u64_be(&mut self, val: u64) -> Result {
        const LEN: usize = core::mem::size_of::<u64>();
        if self.idx + LEN <= self.ptr.len() {
            let v = val.to_be_bytes();
            for i in 0..LEN {
                self.put_u8(v[i])?;
            }
            Ok(())
        } else {
            Err(error::code::EIO)
        }
    }

    pub(crate) fn get_varlen_be(&mut self) -> Result<u64> {
        let v = self.get_u8()?;
        match (v & 0xc0) >> 6 {
            0 => Ok((v & 0x3f) as u64),
            1 => {
                const LEN: usize = core::mem::size_of::<u16>();
                let mut buf = [0; LEN];
                buf[0] = v & 0x3f;
                buf[1] = self.get_u8()?;
                let v = u16::from_be_bytes(buf) as u64;
                Ok(v)
            }
            2 => {
                const LEN: usize = core::mem::size_of::<u32>();
                let mut buf = [0; LEN];
                buf[0] = v & 0x3f;
                buf.copy_from_slice(&self.ptr[self.idx..self.idx + LEN - 1]);
                self.idx += LEN - 1;
                let v = u32::from_be_bytes(buf) as u64;
                Ok(v)
            }
            3 => {
                const LEN: usize = core::mem::size_of::<u64>();
                let mut buf = [0; LEN];
                buf[0] = v & 0x3f;
                buf.copy_from_slice(&self.ptr[self.idx..self.idx + LEN - 1]);
                self.idx += LEN - 1;
                Ok(u64::from_be_bytes(buf))
            }
            _ => Err(error::code::EIO),
        }
    }

    pub(crate) fn put_varlen_u8(&mut self, val: u8) -> Result {
        if 0xc0 & val != 0 {
            return Err(error::code::EIO);
        }
        self.put_u8(val)
    }

    pub(crate) fn put_varlen_u16_be(&mut self, val: u16) -> Result {
        let mut bytes = val.to_be_bytes();
        if 0xc0 & bytes[0] != 0 {
            return Err(error::code::EIO);
        }
        bytes[0] |= 1 << 6;
        for v in bytes {
            self.put_u8(v)?;
        }
        Ok(())
    }

    pub(crate) fn put_varlen_u32_be(&mut self, val: u32) -> Result {
        let mut bytes = val.to_be_bytes();
        if 0xc0 & bytes[0] != 0 {
            return Err(error::code::EIO);
        }
        bytes[0] |= 2 << 6;
        for v in bytes {
            self.put_u8(v)?;
        }
        Ok(())
    }

    pub(crate) fn get_bytes(&mut self, dst: &mut [u8], len: usize) -> Result {
        if dst.len() >= len && self.idx + len <= self.ptr.len() {
            (&mut dst[0..len]).copy_from_slice(&self.ptr[self.idx..self.idx + len]);
            self.idx += len;
            Ok(())
        } else {
            Err(error::code::EIO)
        }
    }

    pub(crate) fn put_bytes(&mut self, src: &[u8]) -> Result {
        if self.ptr.len() > self.get_index() + src.len() {
            self.ptr[self.idx..self.idx + src.len()].copy_from_slice(src);
            self.idx += src.len();
            Ok(())
        } else {
            Err(error::code::EINVAL)
        }
    }
}
