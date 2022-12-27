use crate::buf::Buf;
use kernel::bindings;
use kernel::crypto;
use kernel::error;
use kernel::prelude::*;
use kernel::Result;

pub(crate) enum HashAlgo {
    SHA256,
    SHA384,
}

pub(crate) struct Hkdf {
    hash: &'static CStr,
    hmac: &'static CStr,
}

impl Hkdf {
    pub(crate) fn new(algo: HashAlgo) -> Self {
        match algo {
            HashAlgo::SHA256 => Hkdf {
                hash: kernel::c_str!("sha256"),
                hmac: kernel::c_str!("hmac(sha256)"),
            },
            HashAlgo::SHA384 => Hkdf {
                hash: kernel::c_str!("sha384"),
                hmac: kernel::c_str!("hmac(sha384)"),
            },
        }
    }

    pub(crate) fn transcript_hash(&self, msg: &[u8], output: &mut [u8]) -> Result {
        let hash = crypto::Hash::new(self.hash, 0, 0)?;
        let mut desc = crypto::HashDesc::new(&hash)?;
        desc.init()?;
        desc.update(&msg)?;
        desc.finalize(output)?;
        Ok(())
    }

    pub(crate) fn expand(&self, key: &[u8], info: &[u8], output: &mut [u8]) -> Result {
        let mut hash = crypto::Hash::new(self.hmac, 0, 0)?;
        hash.setkey(key)?;
        let ds = hash.digestsize() as usize;
        let output_len = output.len() as usize;

        let n = output_len / ds + if output_len % ds > 0 { 1 } else { 0 };
        for i in 1..n + 1 {
            let mut desc = crypto::HashDesc::new(&hash)?;
            desc.init()?;

            if i > 1 {
                //prev
                desc.update(&output[(i as usize - 2) * ds..])?;
            }
            desc.update(info)?;
            desc.update(&u8::to_be_bytes(i as u8))?;
            if ds > output_len {
                let mut v = Vec::try_with_capacity(ds)?;
                for _ in 0..ds {
                    v.try_push(0)?;
                }
                desc.finalize(&mut v.as_mut_slice())?;
                for n in 0..output_len {
                    output[n] = v[n];
                }
            } else {
                desc.finalize(&mut output[(i as usize - 1) * ds..])?;
            }
        }

        Ok(())
    }

    pub(crate) fn expand_label(
        &self,
        key: &[u8],
        label: &[u8],
        context: &[u8],
        output: &mut [u8],
    ) -> Result {
        const LABEL_PREFIX: &[u8] = b"tls13 ";
        let len = 2 + 1 + LABEL_PREFIX.len() + label.len() + 1 + context.len();
        let mut info: Vec<u8> = Vec::try_with_capacity(len)?;

        info.try_extend_from_slice(&u16::to_be_bytes(output.len() as u16))?;

        info.try_push((LABEL_PREFIX.len() + label.len()) as u8)?;
        info.try_extend_from_slice(&LABEL_PREFIX)?;
        info.try_extend_from_slice(&label)?;

        info.try_push(context.len() as u8)?;
        info.try_extend_from_slice(&context)?;

        self.expand(key, info.as_slice(), output)
    }

    pub(crate) fn derive_secret(
        &self,
        secret: &[u8],
        label: &[u8],
        message: &[u8],
        output: &mut [u8],
    ) -> Result {
        let hash = crypto::Hash::new(self.hash, 0, 0)?;
        let mut value = Vec::try_with_capacity(hash.digestsize() as usize)?;
        for _ in 0..hash.digestsize() {
            value.try_push(0).unwrap();
        }
        let mut desc = crypto::HashDesc::new(&hash)?;
        desc.init()?;
        desc.update(&message)?;
        desc.finalize(&mut value)?;
        self.expand_label(secret, label, &value, output)
    }

    pub(crate) fn extract(&self, salt: &[u8], ikm: &[u8], output: &mut [u8]) -> Result {
        let mut hash = crypto::Hash::new(self.hmac, 0, 0)?;
        hash.setkey(salt)?;
        let mut desc = crypto::HashDesc::new(&hash)?;
        desc.init()?;
        desc.update(ikm)?;
        desc.finalize(output)
    }
}

fn generate_ecdh_shared_secret(pubkey: &[u8], privkey: &[u8]) -> Result<[u8; 32]> {
    let ecdh_shared_secret: [u8; 32] = [0; 32];
    unsafe {
        let kpp = crypto::Kpp::new(kernel::c_str!("curve25519"), 0, 0)?;
        let _r =
            bindings::crypto_kpp_set_secret(kpp.ptr, privkey.as_ptr() as _, privkey.len() as u32);
        let rq = bindings::kpp_request_alloc(kpp.ptr, bindings::GFP_KERNEL);
        let mut src_sg: bindings::scatterlist = Default::default();
        bindings::sg_init_one(&mut src_sg, pubkey.as_ptr() as _, pubkey.len() as u32);
        bindings::kpp_request_set_input(rq, &mut src_sg, pubkey.len() as u32);

        let mut dst_sg: bindings::scatterlist = Default::default();
        let ecdh_shared_secret_len = ecdh_shared_secret.len();
        bindings::sg_init_one(
            &mut dst_sg,
            ecdh_shared_secret.as_ptr() as _,
            ecdh_shared_secret_len as u32,
        );
        bindings::kpp_request_set_output(rq, &mut dst_sg, ecdh_shared_secret_len as u32);
        bindings::kpp_request_set_callback(rq, 0, None, core::ptr::null_mut());
        bindings::crypto_kpp_generate_public_key(rq);
        bindings::kpp_request_free(rq);
    }
    Ok(ecdh_shared_secret)
}

pub(crate) struct Signature {
    bytes: [u8; Signature::MAX_SIGNATURE_LEN],
    len: usize,
}

impl Signature {
    const MAX_SIGNATURE_LEN: usize = 72;

    fn new(r: &[u8], s: &[u8]) -> Result<Self> {
        let rlen = if r[0] & 0x80 > 0 { 33 } else { 32 };
        let slen = if s[0] & 0x80 > 0 { 33 } else { 32 };

        let len = rlen + slen + 6;

        let mut sig = Signature {
            bytes: [0; Signature::MAX_SIGNATURE_LEN],
            len,
        };
        let mut buf = Buf::new(&mut sig.bytes);

        buf.put_u8(0x30)?;
        buf.put_u8(len as u8 - 2)?;
        buf.put_u8(0x02)?;
        buf.put_u8(rlen as u8)?;
        if r[0] & 0x80 > 0 {
            buf.put_u8(0)?;
        }
        buf.put_bytes(r)?;

        buf.put_u8(0x02)?;
        buf.put_u8(slen as u8)?;
        if s[0] & 0x80 > 0 {
            buf.put_u8(0)?;
        }
        buf.put_bytes(s)?;

        Ok(sig)
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

enum HandshakeType {
    ServerHello = 2,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateVerify = 15,
    Finished = 20,
}

enum SignAlgoType {
    EcdsaSecp256r1Sha256 = 0x0403,
}

pub(crate) struct ServerContext {
    buf: *mut u8,
    buf_idx: usize,

    client_pubkey: [u8; 32],
    server_privkey: [u8; 32],

    hs_secret: [u8; 32],
    client_hs_traffic_secret: [u8; 32],
    server_hs_traffic_secret: [u8; 32],
    client_app_traffic_secret: [u8; 32],
    server_app_traffic_secret: [u8; 32],
}

impl ServerContext {
    pub(crate) fn new(privkey: &[u8]) -> Result<Self> {
        let mut server_privkey = [0; 32];
        server_privkey.copy_from_slice(privkey);
        let p = unsafe { bindings::__kmalloc(8192, bindings::GFP_KERNEL) };
        if p.is_null() {
            return Err(error::code::ENOMEM);
        }
        Ok(ServerContext {
            buf: p as *mut u8,
            buf_idx: 0,
            client_pubkey: [0; 32],
            server_privkey,
            hs_secret: [0; 32],
            client_hs_traffic_secret: [0; 32],
            server_hs_traffic_secret: [0; 32],
            client_app_traffic_secret: [0; 32],
            server_app_traffic_secret: [0; 32],
        })
    }

    pub(crate) fn server_handshake_secret(&self) -> &[u8] {
        &self.server_hs_traffic_secret
    }

    pub(crate) fn client_handshake_secret(&self) -> &[u8] {
        &self.client_hs_traffic_secret
    }

    pub(crate) fn server_app_secret(&self) -> &[u8] {
        &self.server_app_traffic_secret
    }

    pub(crate) fn client_app_secret(&self) -> &[u8] {
        &self.client_app_traffic_secret
    }

    pub(crate) fn generate_verify(&mut self) -> Result<[u8; 32]> {
        let h = Hkdf::new(HashAlgo::SHA256);
        let mut finished_key: [u8; 32] = [0; 32];
        let context: [u8; 0] = [];
        h.expand_label(
            &self.server_hs_traffic_secret,
            b"finished",
            &context,
            &mut finished_key,
        )?;

        let mut value: [u8; 32] = [0; 32];
        h.transcript_hash(self.bytes(), &mut value)?;

        let mut output: [u8; 32] = [0; 32];
        h.extract(&finished_key, &value, &mut output)?;

        Ok(output)
    }

    pub(crate) fn key_schedule_for_handshake(&mut self) -> Result {
        let secret = {
            let mut early_secret = [0; 32];
            let salt = [0u8; 32];
            let h = Hkdf::new(HashAlgo::SHA256);
            h.extract(&salt, &salt, &mut early_secret)?;
            early_secret
        };

        let mut early_secret = [0; 32];
        let h = Hkdf::new(HashAlgo::SHA256);
        h.derive_secret(&secret, b"derived", &[0; 0], &mut early_secret)?;

        let ecdh_shared_secret =
            generate_ecdh_shared_secret(&self.client_pubkey, &self.server_privkey)?;
        h.extract(&early_secret, &ecdh_shared_secret, &mut self.hs_secret)?;

        let mut client_hs_traffic_secret = [0u8; 32];
        h.derive_secret(
            &self.hs_secret,
            b"c hs traffic",
            &self.bytes(),
            &mut client_hs_traffic_secret,
        )?;
        self.client_hs_traffic_secret
            .copy_from_slice(&client_hs_traffic_secret);

        let mut server_hs_traffic_secret = [0u8; 32];
        h.derive_secret(
            &self.hs_secret,
            b"s hs traffic",
            &self.bytes(),
            &mut server_hs_traffic_secret,
        )?;
        self.server_hs_traffic_secret
            .copy_from_slice(&server_hs_traffic_secret);
        Ok(())
    }

    pub(crate) fn key_schedule_for_app(&mut self) -> Result {
        let mut secret_for_master = [0u8; 32];
        let h = Hkdf::new(HashAlgo::SHA256);
        h.derive_secret(
            &self.hs_secret,
            b"derived",
            &[0u8; 0],
            &mut secret_for_master,
        )?;

        let mut master_secret = [0u8; 32];
        let value: [u8; 32] = [0; 32];
        h.extract(&secret_for_master, &value, &mut master_secret)?;

        let mut client_app_traffic_secret = [0u8; 32];
        h.derive_secret(
            &master_secret,
            b"c ap traffic",
            &self.bytes(),
            &mut client_app_traffic_secret,
        )?;
        self.client_app_traffic_secret
            .copy_from_slice(&client_app_traffic_secret);

        let mut server_app_traffic_secret = [0u8; 32];
        h.derive_secret(
            &master_secret,
            b"s ap traffic",
            self.bytes(),
            &mut server_app_traffic_secret,
        )?;
        self.server_app_traffic_secret
            .copy_from_slice(&server_app_traffic_secret);

        Ok(())
    }

    fn message_hash(&mut self) -> Result<[u8; 32]> {
        let mut value: [u8; 32] = [0; 32];
        Hkdf::new(HashAlgo::SHA256).transcript_hash(self.bytes(), &mut value)?;
        Ok(value)
    }

    pub(crate) fn signature(&mut self) -> Result<Signature> {
        let msg1 = [0x20u8; 64];
        let msg2 = b"TLS 1.3, server CertificateVerify";
        let msg3 = [0u8; 1];
        let msg4 = self.message_hash()?;

        let mut msg = [0u8; 130];
        let mut offset = 0;
        msg[offset..offset + msg1.len()].copy_from_slice(&msg1);
        offset += msg1.len();
        msg[offset..offset + msg2.len()].copy_from_slice(msg2);
        offset += msg2.len();
        msg[offset..offset + msg3.len()].copy_from_slice(&msg3);
        offset += msg3.len();
        msg[offset..offset + msg4.len()].copy_from_slice(&msg4);
        offset += msg4.len();

        let mut value: [u8; 32] = [0; 32];
        let h = Hkdf::new(HashAlgo::SHA256);
        h.transcript_hash(&msg[..offset], &mut value)?;

        let t = crypto::Akcipher::new(kernel::c_str!("ecdsa-nist-p256"), 0, 0)?;
        unsafe {
            let r = bindings::crypto_akcipher_set_priv_key(
                t.ptr,
                self.server_privkey.as_ptr() as _,
                self.server_privkey.len() as u32,
            );
            if r != 0 {
                pr_info!("failed to set privkey {}", r);
                return Err(error::code::EINVAL);
            }
        }
        let sign: [u8; 64] = [0; 64];
        let mut sg_src: bindings::scatterlist = Default::default();
        unsafe {
            bindings::sg_init_one(&mut sg_src, value.as_ptr() as _, value.len() as u32);
        }
        let mut sg_dst: bindings::scatterlist = Default::default();
        unsafe {
            bindings::sg_init_one(&mut sg_dst, sign.as_ptr() as _, sign.len() as u32);
        }

        let req = crypto::AkcipherRequest::new(&t)?;
        unsafe {
            bindings::akcipher_request_set_callback(req.ptr, 0, None, core::ptr::null_mut());
            bindings::akcipher_request_set_crypt(
                req.ptr,
                &mut sg_src,
                &mut sg_dst,
                value.len() as u32,
                sign.len() as u32,
            );

            let r = bindings::crypto_akcipher_sign(req.ptr);
            if r != 0 {
                pr_info!("failed to sign {}", r);
                return Err(error::code::EINVAL);
            }
        }

        Signature::new(&sign[0..32], &sign[32..])
    }

    pub(crate) fn generate_public_key(&self) -> Result<[u8; 32]> {
        let generated_public_key = [0u8; 32];

        let kpp = crypto::Kpp::new(kernel::c_str!("curve25519"), 0, 0)?;
        unsafe {
            bindings::crypto_kpp_set_secret(
                kpp.ptr,
                self.server_privkey.as_ptr() as _,
                self.server_privkey.len() as u32,
            );

            let rq = bindings::kpp_request_alloc(kpp.ptr, bindings::GFP_KERNEL);
            (*rq).src = core::ptr::null_mut();
            let mut sg: bindings::scatterlist = Default::default();

            let dst_data_len = generated_public_key.len();
            bindings::sg_init_one(
                &mut sg,
                generated_public_key.as_ptr() as _,
                dst_data_len as u32,
            );
            bindings::kpp_request_set_output(rq, &mut sg, dst_data_len as u32);
            bindings::kpp_request_set_callback(rq, 0, None, core::ptr::null_mut());
            bindings::crypto_kpp_generate_public_key(rq);
            bindings::kpp_request_free(rq);
        }

        Ok(generated_public_key)
    }

    pub(crate) fn record(&mut self, bytes: &[u8]) -> Result {
        let payload = unsafe { core::slice::from_raw_parts_mut(self.buf, 8192) };
        // TODO: handle overflow
        payload[self.buf_idx..self.buf_idx + bytes.len()].copy_from_slice(bytes);
        self.buf_idx += bytes.len();

        Ok(())
    }

    pub(crate) fn write(&mut self, bytes: &mut [u8]) -> Result {
        self.record(&bytes)?;
        let mut buf = Buf::new(bytes);

        match buf.get_u8()? {
            // CLIENT HELLO
            1 => {
                let _len = buf.get_u24_be()?;
                let _ver = buf.get_u16_be()?;
                let mut random = [0; 32];
                for i in 0..32 {
                    random[i] = buf.get_u8()?;
                }

                let _sid = buf.get_u8()?;
                let clen = buf.get_u16_be()? / 2;
                for _ in 0..clen {
                    let _ = buf.get_u16_be()?;
                }
                let compression_methods = buf.get_u8()?;
                for _ in 0..compression_methods {
                    let _ = buf.get_u8()?;
                }
                let mut extension_len = buf.get_u16_be()?;
                while extension_len > 0 {
                    let t = buf.get_u16_be()?;
                    let l = buf.get_u16_be()?;
                    if t == 51 {
                        let _ = buf.get_u16_be()?;
                        let _group = buf.get_u16_be()?;
                        let keylen = buf.get_u16_be()?;

                        for i in 0..keylen {
                            self.client_pubkey[i as usize] = buf.get_u8()?;
                        }
                    } else {
                        for _ in 0..l {
                            let _ = buf.get_u8()?;
                        }
                    }
                    extension_len -= 4 + l;
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn bytes(&self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.buf, self.buf_idx) }
    }
}

const TLS_12_VERSION: u16 = 0x0303;
const TLS_13_VERSION: u16 = 0x0304;

enum CipherSuite {
    Aes128GcmSha256 = 0x1301,
}

impl Drop for ServerContext {
    fn drop(&mut self) {
        unsafe { bindings::kfree(self.buf as *mut core::ffi::c_void) }
    }
}

enum ExtensionType {
    SupportedVersion = 43,
    KeyShare = 51,
}

struct ExtensionKeyShare {}

impl ExtensionKeyShare {
    fn serialize(buf: &mut Buf<'_>, pubkey: &[u8]) -> Result {
        buf.put_u16_be(ExtensionType::KeyShare as u16)?;
        buf.put_u16_be(pubkey.len() as u16 + 4)?;
        // group: x25519
        buf.put_u16_be(29)?;
        buf.put_u16_be(pubkey.len() as u16)?;
        buf.put_bytes(pubkey)
    }
}

struct ExtensionVersion {}

impl ExtensionVersion {
    fn serialize(buf: &mut Buf<'_>) -> Result {
        buf.put_u16_be(ExtensionType::SupportedVersion as u16)?;
        buf.put_u16_be(2)?;
        buf.put_u16_be(TLS_13_VERSION)
    }
}

pub(crate) struct ServerHello {}

impl ServerHello {
    pub(crate) fn serialize(bytes: &mut [u8], pubkey: &[u8]) -> Result<usize> {
        let mut buf = Buf::new(bytes);

        // for now, uses const value for easy debugging
        const RANDOM: [u8; 32] = [
            0x7a, 0x2c, 0x44, 0x44, 0x82, 0xeb, 0x0b, 0xd8, 0x3a, 0xdd, 0x4b, 0x8b, 0x17, 0x34,
            0x57, 0x03, 0xc8, 0x6c, 0xcb, 0xb9, 0x29, 0xce, 0x72, 0xc5, 0xde, 0xfb, 0xe5, 0x6f,
            0x1b, 0x7b, 0x3a, 0x28,
        ];

        buf.put_u8(HandshakeType::ServerHello as u8)?;
        // len: set later
        buf.put_u24_be(0)?;
        buf.put_u16_be(TLS_12_VERSION)?;

        buf.put_bytes(&RANDOM)?;
        // session ID len
        buf.put_u8(0)?;
        buf.put_u16_be(CipherSuite::Aes128GcmSha256 as u16)?;
        // Compression Method: null
        buf.put_u8(0)?;

        // extention len: set later
        buf.put_u16_be(0)?;
        let ext_start = buf.get_index();
        // extensions
        ExtensionKeyShare::serialize(&mut buf, pubkey)?;
        ExtensionVersion::serialize(&mut buf)?;

        let ext_end = buf.get_index();

        buf.set_index(ext_start - 2);
        buf.put_u16_be((ext_end - ext_start) as u16)?;
        buf.set_index(1);
        buf.put_u24_be(ext_end as u32 - 4)?;

        Ok(ext_end)
    }
}

pub(crate) struct EncryptedExtensions {}

impl EncryptedExtensions {
    pub(crate) fn serialize(bytes: &mut [u8], dcid: &[u8], scid: &[u8]) -> Result<usize> {
        let mut buf = Buf::new(bytes);

        buf.put_u8(HandshakeType::EncryptedExtensions as u8)?;
        // len set later
        buf.put_u24_be(0)?;
        buf.put_u16_be(0)?;

        // application layer protocol negotiation
        buf.put_u16_be(16)?;
        buf.put_u16_be(8)?;
        buf.put_u16_be(6)?;
        buf.put_u8(5)?;
        const ALPN: [u8; 5] = [0x68, 0x71, 0x2d, 0x32, 0x39];
        buf.put_bytes(&ALPN)?;

        // server name
        buf.put_u16_be(0)?;
        buf.put_u16_be(0)?;

        // quic transport parameters
        buf.put_u16_be(57)?;
        buf.put_u16_be(105)?;
        // param: max idle timeout
        buf.put_u8(0x01)?;
        buf.put_u8(2)?;
        buf.put_varlen_u16_be(10000)?;
        // param max_udp_payload_size
        buf.put_u8(0x03)?;
        buf.put_u8(2)?;
        buf.put_varlen_u16_be(1480)?;
        // param initial_max_data
        buf.put_u8(0x04)?;
        buf.put_u8(8)?;
        buf.put_u64_be(!0)?;
        // param: initial_max_stream_data_bidi_local
        buf.put_u8(0x05)?;
        buf.put_u8(4)?;
        buf.put_varlen_u32_be(125000)?;
        // param: initial_max_stream_data_bidi_remote
        buf.put_u8(0x06)?;
        buf.put_u8(4)?;
        buf.put_varlen_u32_be(125000)?;
        // param: initial_max_stream_data_bidi_uni
        buf.put_u8(0x07)?;
        buf.put_u8(4)?;
        buf.put_varlen_u32_be(125000)?;
        // param: initial_max_stream_bidi
        buf.put_u8(0x08)?;
        buf.put_u8(2)?;
        buf.put_varlen_u16_be(100)?;
        // param: active_connection_id_limit
        buf.put_u8(0x0e)?;
        buf.put_u8(1)?;
        buf.put_varlen_u8(5)?;
        // param: GREASE
        buf.put_u8(0x40)?;
        buf.put_u8(0xb6)?;
        buf.put_u8(0)?;
        // param: stateless_reset_token
        buf.put_u8(0x02)?;
        buf.put_u8(16)?;
        // FIXME
        const TOKEN: [u8; 16] = [
            0x08, 0x04, 0xc1, 0x05, 0x43, 0xd8, 0xc4, 0xb4, 0xfa, 0xe6, 0x06, 0x5e, 0x3e, 0x26,
            0x42, 0x0f,
        ];
        buf.put_bytes(&TOKEN)?;

        // param: max_datagram_frame_size
        buf.put_u8(0x20)?;
        buf.put_u8(4)?;
        buf.put_varlen_u32_be(65535)?;

        // param: original_destination_connection_id
        buf.put_u8(0x00)?;
        buf.put_u8(dcid.len() as u8)?;
        buf.put_bytes(dcid)?;

        // param: initial_source_connection_id
        buf.put_u8(0x0f)?;
        buf.put_u8(scid.len() as u8)?;
        buf.put_bytes(scid)?;

        // param: grease_quic_bit
        buf.put_varlen_u16_be(0x2ab2)?;
        buf.put_u8(0)?;

        let len = buf.get_index();
        buf.set_index(1);
        buf.put_u24_be(len as u32 - 4)?;
        buf.put_u16_be(len as u16 - 6)?;

        Ok(len)
    }
}

pub(crate) struct Certificate {}

impl Certificate {
    pub(crate) fn serialize(bytes: &mut [u8], cert: &[u8]) -> Result<usize> {
        let mut buf = Buf::new(bytes);

        let cert_len = cert.len() as u32;
        buf.put_u8(HandshakeType::Certificate as u8)?;
        buf.put_u24_be(cert_len + 9)?;
        buf.put_u8(0)?;
        buf.put_u24_be(cert_len + 5)?;
        buf.put_u24_be(cert_len)?;
        buf.put_bytes(cert)?;
        buf.put_u16_be(0)?;

        Ok(buf.get_index())
    }
}

pub(crate) struct CertificateVerify {}

impl CertificateVerify {
    pub(crate) fn serialize(bytes: &mut [u8], signature: &[u8]) -> Result<usize> {
        let mut buf = Buf::new(bytes);

        buf.put_u8(HandshakeType::CertificateVerify as u8)?;
        buf.put_u24_be(signature.len() as u32 + 4)?;
        buf.put_u16_be(SignAlgoType::EcdsaSecp256r1Sha256 as u16)?;
        buf.put_u16_be(signature.len() as u16)?;
        buf.put_bytes(signature)?;

        Ok(buf.get_index())
    }
}

pub(crate) struct Finished {}

impl Finished {
    pub(crate) fn serialize(bytes: &mut [u8], verify: &[u8]) -> Result<usize> {
        let mut buf = Buf::new(bytes);

        buf.put_u8(HandshakeType::Finished as u8)?;
        buf.put_u24_be(verify.len() as u32)?;
        buf.put_bytes(verify)?;

        Ok(buf.get_index())
    }
}
