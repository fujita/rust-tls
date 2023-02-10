// SPDX-License-Identifier: GPL-2.0

use crate::buf::Buf;
use crate::crypto;
use kernel::bindings;
use kernel::crypto::{Shash, ShashDesc};
use kernel::error::{self, Result};
use kernel::net;
use kernel::prelude::*;

const TLS_12_VERSION: u16 = 0x0303;
const TLS_13_VERSION: u16 = 0x0304;

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
        let hash = Shash::new(self.hash, 0, 0)?;
        let mut desc = ShashDesc::new(&hash)?;
        desc.init()?;
        desc.update(&msg)?;
        desc.finalize(output)?;
        Ok(())
    }

    pub(crate) fn expand(&self, key: &[u8], info: &[u8], output: &mut [u8]) -> Result {
        let mut hash = Shash::new(self.hmac, 0, 0)?;
        hash.setkey(key)?;
        let ds = hash.digestsize() as usize;
        let output_len = output.len() as usize;

        let n = output_len / ds + if output_len % ds > 0 { 1 } else { 0 };
        for i in 1..n + 1 {
            let mut desc = ShashDesc::new(&hash)?;
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
        let hash = Shash::new(self.hash, 0, 0)?;
        let mut value = Vec::try_with_capacity(hash.digestsize() as usize)?;
        for _ in 0..hash.digestsize() {
            value.try_push(0).unwrap();
        }
        let mut desc = ShashDesc::new(&hash)?;
        desc.init()?;
        desc.update(&message)?;
        desc.finalize(&mut value)?;
        self.expand_label(secret, label, &value, output)
    }

    pub(crate) fn extract(&self, salt: &[u8], ikm: &[u8], output: &mut [u8]) -> Result {
        let mut hash = Shash::new(self.hmac, 0, 0)?;
        hash.setkey(salt)?;
        let mut desc = ShashDesc::new(&hash)?;
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

#[derive(Clone, Copy, Debug, PartialEq)]
enum HandshakeType {
    Unknown,
    ClientHello = 1,
    ServerHello = 2,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateVerify = 15,
    Finished = 20,
}

impl From<u8> for HandshakeType {
    fn from(v: u8) -> HandshakeType {
        if v == HandshakeType::ClientHello as u8 {
            HandshakeType::ClientHello
        } else if v == HandshakeType::ServerHello as u8 {
            HandshakeType::ServerHello
        } else if v == HandshakeType::EncryptedExtensions as u8 {
            HandshakeType::EncryptedExtensions
        } else if v == HandshakeType::Certificate as u8 {
            HandshakeType::Certificate
        } else if v == HandshakeType::CertificateVerify as u8 {
            HandshakeType::CertificateVerify
        } else if v == HandshakeType::Finished as u8 {
            HandshakeType::Finished
        } else {
            HandshakeType::Unknown
        }
    }
}

#[derive(PartialEq)]
enum ContentType {
    Unknown,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    Application = 23,
}

impl From<u8> for ContentType {
    fn from(v: u8) -> ContentType {
        if v == ContentType::ChangeCipherSpec as u8 {
            ContentType::ChangeCipherSpec
        } else if v == ContentType::Alert as u8 {
            ContentType::Alert
        } else if v == ContentType::Handshake as u8 {
            ContentType::Handshake
        } else if v == ContentType::Application as u8 {
            ContentType::Application
        } else {
            ContentType::Unknown
        }
    }
}

fn tcp_set_cork(socket: &mut net::Socket, val: bool) {
    let sock: *mut bindings::socket = socket.sock;
    unsafe { bindings::tcp_sock_set_cork((*sock).sk, val) }
}

enum Record<'a> {
    Handshake(&'a mut Message),
    Alert(u8, u8),
}

impl Record<'_> {
    const HEADER_LEN: usize = 5;
}

struct RecWriter {
    seq_tx: u64,
}

impl RecWriter {
    fn new() -> Result<Self> {
        Ok(RecWriter { seq_tx: 0 })
    }

    fn flush(&mut self, socket: &mut net::Socket) {
        tcp_set_cork(socket, false);
        tcp_set_cork(socket, true);
    }

    fn put(
        &mut self,
        rec: &Record<'_>,
        info: &mut CryptoInfo,
        socket: &mut net::Socket,
    ) -> Result<usize> {
        let mut buf = Buf::new_with_capacity(8192)?;

        let (content_type, mut payload_len) = match rec {
            Record::Handshake(msg) => {
                let payload_len = msg.encode(info, &mut buf)?;
                if payload_len == 0 {
                    return Ok(0);
                }
                info.bytes
                    .try_extend_from_slice(&buf.as_ref()[0..payload_len])?;
                (ContentType::Handshake as u8, payload_len)
            }
            Record::Alert(level, description) => {
                buf.put_u8(*level)?;
                buf.put_u8(*description)?;
                (ContentType::Alert as u8, 2)
            }
        };

        let mut hdr_buf = Buf::new_with_capacity(Record::HEADER_LEN)?;
        let mut tag_size = 0;

        if info.is_plaintext {
            hdr_buf.put_u8(content_type)?;
            hdr_buf.put_u16_be(TLS_12_VERSION)?;
            hdr_buf.put_u16_be(payload_len as _)?;
        } else {
            tag_size = info.tag_size() as usize;
            buf.put_u8(content_type)?;
            payload_len += 1;

            hdr_buf.put_u8(ContentType::Application as u8)?;
            hdr_buf.put_u16_be(TLS_12_VERSION)?;
            hdr_buf.put_u16_be((payload_len + tag_size) as u16)?;

            let aead = crypto::Aead::new(kernel::c_str!("gcm(aes)"), 0, 0)?;
            let number_bytes = self.seq_tx.to_be_bytes();
            self.seq_tx += 1;

            let mut nonce: [u8; 12] = [0; 12];
            for i in 0..number_bytes.len() {
                nonce[nonce.len() - number_bytes.len() + i] = number_bytes[i];
            }

            for i in 0..nonce.len() {
                nonce[i] = nonce[i] ^ info.server_hs_keys.iv[i];
            }

            unsafe {
                bindings::crypto_aead_setkey(
                    aead.ptr,
                    info.server_hs_keys.key.as_ptr() as _,
                    info.server_hs_keys.key.len() as u32,
                );
                let mut sg: [bindings::scatterlist; 2] = [Default::default(); 2];
                bindings::sg_init_table(sg.as_mut_ptr(), 2);
                bindings::sg_set_buf(
                    &mut sg[0],
                    hdr_buf.as_mut().as_mut_ptr().cast(),
                    Record::HEADER_LEN as u32,
                );
                bindings::sg_set_buf(
                    &mut sg[1],
                    buf.as_mut().as_mut_ptr().cast(),
                    (payload_len + tag_size) as u32,
                );

                let req = bindings::aead_request_alloc(aead.ptr, bindings::GFP_KERNEL);
                bindings::aead_request_set_ad(req, Record::HEADER_LEN as u32);
                bindings::aead_request_set_crypt(
                    req,
                    sg.as_mut_ptr(),
                    sg.as_mut_ptr(),
                    payload_len as u32,
                    nonce.as_mut_ptr(),
                );
                bindings::aead_request_set_callback(req, 0, None, core::ptr::null_mut());
                let _ = bindings::crypto_aead_encrypt(req);
            }
        }

        socket.sendmsg(&mut [
            hdr_buf.as_mut(),
            &mut buf.as_mut()[0..payload_len + tag_size],
        ])
    }
}

struct RecReader {
    seq_rx: u64,
}

impl RecReader {
    fn new() -> Result<Self> {
        Ok(RecReader { seq_rx: 0 })
    }

    fn get(&mut self, info: &mut CryptoInfo, socket: &mut net::Socket) -> Result<(u8, Buf)> {
        let mut hdr_buf = Buf::new_with_capacity(5)?;
        socket.recvmsg(&mut [hdr_buf.as_mut()], net::MSG_WAITALL)?;

        let mut record_type = hdr_buf.get_u8()?;
        let _ = hdr_buf.get_u16_be()?;
        let mut len = hdr_buf.get_u16_be()?;

        let mut buf = Buf::new_with_capacity(len as usize)?;
        socket.recvmsg(&mut [buf.as_mut()], net::MSG_WAITALL)?;

        if record_type == ContentType::Application as u8 {
            let aead = crypto::Aead::new(kernel::c_str!("gcm(aes)"), 0, 0)?;
            let number_bytes = self.seq_rx.to_be_bytes();
            self.seq_rx += 1;
            let mut nonce: [u8; 12] = [0; 12];
            for i in 0..number_bytes.len() {
                nonce[nonce.len() - number_bytes.len() + i] = number_bytes[i];
            }
            for i in 0..nonce.len() {
                nonce[i] = nonce[i] ^ info.client_hs_keys.iv[i];
            }

            unsafe {
                bindings::crypto_aead_setkey(
                    aead.ptr,
                    info.client_hs_keys.key.as_ptr() as _,
                    info.client_hs_keys.key.len() as _,
                );
                let mut sg: [bindings::scatterlist; 2] = [Default::default(); 2];
                bindings::sg_init_table(sg.as_mut_ptr(), 2);
                bindings::sg_set_buf(&mut sg[0], hdr_buf.as_mut().as_mut_ptr().cast(), 5);
                bindings::sg_set_buf(&mut sg[1], buf.as_mut().as_mut_ptr().cast(), len as u32);

                let req = bindings::aead_request_alloc(aead.ptr, bindings::GFP_KERNEL);
                bindings::aead_request_set_ad(req, 5 as u32);
                bindings::aead_request_set_crypt(
                    req,
                    sg.as_mut_ptr(),
                    sg.as_mut_ptr(),
                    len as u32,
                    nonce.as_mut_ptr(),
                );
                bindings::aead_request_set_callback(req, 0, None, core::ptr::null_mut());
                bindings::crypto_aead_decrypt(req);

                // tag
                len -= info.tag_size();
                // record_type
                record_type = buf.as_ref()[len as usize - 1];
                len -= 1;
            }
        }
        buf.resize(len as usize)?;

        Ok((record_type, buf))
    }
}

pub(crate) struct ServerConfig {
    privkey: [u8; 32],
    certificate: Vec<u8>,
}

impl ServerConfig {
    pub(crate) fn new(key: &[u8], cert: &[u8]) -> Result<Self> {
        let mut privkey = [0; 32];
        privkey.copy_from_slice(key);
        let mut certificate = Vec::new();
        certificate.try_extend_from_slice(cert)?;

        Ok(ServerConfig {
            privkey,
            certificate,
        })
    }

    fn context(self) -> Result<CryptoInfo> {
        let pubkey = CryptoInfo::generate_public_key(&self.privkey)?;
        Ok(CryptoInfo {
            is_plaintext: true,
            pubkey,
            server_cert: self.certificate,
            server_privkey: self.privkey,
            client_pubkey: [0; 32],
            bytes: Vec::new(),
            verify_data: Vec::try_with_capacity(32)?,
            hs_secret: [0; 32],
            client_hs_traffic_secret: [0; 32],
            server_hs_traffic_secret: [0; 32],
            client_app_traffic_secret: [0; 32],
            server_app_traffic_secret: [0; 32],

            client_hs_keys: KeySet::default(),
            server_hs_keys: KeySet::default(),
            client_app_keys: KeySet::default(),
            server_app_keys: KeySet::default(),
        })
    }
}

pub(crate) struct Server {}

impl Server {
    pub(crate) fn negotiate(config: ServerConfig, socket: &mut net::Socket) -> Result<Context> {
        let mut state = Message::new();
        let mut info = config.context()?;

        let mut rec_writer = RecWriter::new()?;
        let mut rec_reader = RecReader::new()?;

        tcp_set_cork(socket, true);

        loop {
            if state.is_writer() {
                rec_writer.put(&Record::Handshake(&mut state), &mut info, socket)?;
            } else {
                rec_writer.flush(socket);

                loop {
                    let (record_type, mut buf) = rec_reader.get(&mut info, socket)?;
                    match ContentType::from(record_type) {
                        ContentType::Handshake => {
                            if let Ok(t) = Message::decode(&mut info, &mut buf) {
                                if state.handshake_type() != t {
                                    pr_info!("unexpected handshake message {:?}, {:?}", state, t);
                                    // send alert
                                }
                                match t {
                                    HandshakeType::ClientHello => {
                                        info.bytes.try_extend_from_slice(&buf.as_ref()[0..])?;
                                    }
                                    _ => {}
                                }
                            }
                            break;
                        }
                        ContentType::Application => {
                            pr_info!("should not happen");
                        }
                        ContentType::ChangeCipherSpec => {
                            pr_info!("ignore change cipher");
                        }
                        ContentType::Alert => {
                            pr_info!("alert");
                        }
                        ContentType::Unknown => {
                            return Err(EIO);
                        }
                    }
                }
            }

            match state {
                Message::ClientHello(_) => {
                    // check version, cipher, key exchange
                }
                Message::ServerHello(_) => {
                    info.key_schedule_for_handshake()?;
                    info.client_hs_keys = KeySet::new(&info.client_hs_traffic_secret)?;
                    info.server_hs_keys = KeySet::new(&info.server_hs_traffic_secret)?;

                    info.is_plaintext = false;
                }
                Message::ServerCert(_) => {}
                Message::ServerFinished(_) => {
                    info.key_schedule_for_app()?;
                    info.client_app_keys = KeySet::new(&info.client_app_traffic_secret)?;
                    info.server_app_keys = KeySet::new(&info.server_app_traffic_secret)?;
                }
                Message::ClientFinished(_) => {
                    pr_info!("VERIFY1: {:?}", info.generate_c_verify()?);
                    pr_info!("VERIFY2: {:?}", &info.verify_data);
                }
                _ => {}
            }

            state = match state.next() {
                Some(n) => n,
                None => break,
            };
        }
        rec_writer.flush(socket);

        Ok(info.into())
    }
}

#[derive(Clone, Copy, Default)]
struct KeySet {
    key: [u8; 16],
    iv: [u8; 12],
}

impl KeySet {
    fn new(secret: &[u8]) -> Result<Self> {
        let context: [u8; 0] = [];
        let h = Hkdf::new(HashAlgo::SHA256);

        let mut key: [u8; 16] = [0; 16];
        h.expand_label(&secret, b"key", &context, &mut key)?;

        let mut iv: [u8; 12] = [0; 12];
        h.expand_label(&secret, b"iv", &context, &mut iv)?;

        Ok(KeySet { key, iv })
    }
}

pub(crate) struct Context {
    client_app_keys: KeySet,
    server_app_keys: KeySet,
}

impl Context {
    pub(crate) fn client_salt(&self) -> &[u8] {
        &self.client_app_keys.iv[0..4]
    }

    pub(crate) fn client_iv(&self) -> &[u8] {
        &self.client_app_keys.iv[4..]
    }

    pub(crate) fn client_key(&self) -> &[u8] {
        &self.client_app_keys.key
    }

    pub(crate) fn server_salt(&self) -> &[u8] {
        &self.server_app_keys.iv[0..4]
    }

    pub(crate) fn server_iv(&self) -> &[u8] {
        &self.server_app_keys.iv[4..]
    }

    pub(crate) fn server_key(&self) -> &[u8] {
        &self.server_app_keys.key
    }
}

impl From<CryptoInfo> for Context {
    fn from(info: CryptoInfo) -> Context {
        Context {
            client_app_keys: info.client_app_keys,
            server_app_keys: info.server_app_keys,
        }
    }
}

struct CryptoInfo {
    pubkey: [u8; 32],

    server_cert: Vec<u8>,
    server_privkey: [u8; 32],
    client_pubkey: [u8; 32],
    bytes: Vec<u8>,
    verify_data: Vec<u8>,

    hs_secret: [u8; 32],
    client_hs_traffic_secret: [u8; 32],
    server_hs_traffic_secret: [u8; 32],
    client_app_traffic_secret: [u8; 32],
    server_app_traffic_secret: [u8; 32],

    client_hs_keys: KeySet,
    server_hs_keys: KeySet,
    client_app_keys: KeySet,
    server_app_keys: KeySet,

    is_plaintext: bool,
}

impl CryptoInfo {
    fn tag_size(&self) -> u16 {
        16
    }

    fn generate_public_key(server_privkey: &[u8]) -> Result<[u8; 32]> {
        let generated_pubkey = [0u8; 32];

        let kpp = crypto::Kpp::new(kernel::c_str!("curve25519"), 0, 0)?;
        unsafe {
            bindings::crypto_kpp_set_secret(
                kpp.ptr,
                server_privkey.as_ptr() as _,
                server_privkey.len() as u32,
            );

            let rq = bindings::kpp_request_alloc(kpp.ptr, bindings::GFP_KERNEL);
            (*rq).src = core::ptr::null_mut();
            let mut sg: bindings::scatterlist = Default::default();

            let dst_data_len = generated_pubkey.len();
            bindings::sg_init_one(&mut sg, generated_pubkey.as_ptr() as _, dst_data_len as u32);
            bindings::kpp_request_set_output(rq, &mut sg, dst_data_len as u32);
            bindings::kpp_request_set_callback(rq, 0, None, core::ptr::null_mut());
            bindings::crypto_kpp_generate_public_key(rq);
            bindings::kpp_request_free(rq);
        }

        Ok(generated_pubkey)
    }

    fn generate_verify(&self) -> Result<[u8; 32]> {
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
        h.transcript_hash(&self.bytes, &mut value)?;

        let mut output: [u8; 32] = [0; 32];
        h.extract(&finished_key, &value, &mut output)?;

        Ok(output)
    }

    fn do_generate_verify(&self, key: &[u8]) -> Result<[u8; 32]> {
        let h = Hkdf::new(HashAlgo::SHA256);
        let mut finished_key: [u8; 32] = [0; 32];
        let context: [u8; 0] = [];
        h.expand_label(key, b"finished", &context, &mut finished_key)?;

        let mut value: [u8; 32] = [0; 32];
        h.transcript_hash(&self.bytes, &mut value)?;

        let mut output: [u8; 32] = [0; 32];
        h.extract(&finished_key, &value, &mut output)?;

        Ok(output)
    }

    fn generate_c_verify(&self) -> Result<[u8; 32]> {
        self.do_generate_verify(&self.client_hs_traffic_secret)
    }

    fn message_hash(&self) -> Result<[u8; 32]> {
        let mut value: [u8; 32] = [0; 32];
        Hkdf::new(HashAlgo::SHA256).transcript_hash(&self.bytes, &mut value)?;
        Ok(value)
    }

    fn format_signature(r: &[u8], s: &[u8]) -> Result<Buf> {
        let rlen = if r[0] & 0x80 > 0 { 33 } else { 32 };
        let slen = if s[0] & 0x80 > 0 { 33 } else { 32 };

        let len = rlen + slen + 6;

        let mut buf = Buf::new_with_capacity(len)?;

        buf.put_u8(0x30)?;
        buf.put_u8(len as u8 - 2)?;
        buf.put_u8(0x02)?;
        buf.put_u8(rlen as u8)?;
        if r[0] & 0x80 > 0 {
            buf.put_u8(0)?;
        }
        buf.put_slice(r)?;

        buf.put_u8(0x02)?;
        buf.put_u8(slen as u8)?;
        if s[0] & 0x80 > 0 {
            buf.put_u8(0)?;
        }
        buf.put_slice(s)?;

        Ok(buf)
    }

    fn generate_signature(&self) -> Result<Buf> {
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
        error::to_result(unsafe {
            bindings::crypto_akcipher_set_priv_key(
                t.ptr,
                self.server_privkey.as_ptr() as _,
                self.server_privkey.len() as u32,
            )
        })?;

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

            error::to_result(bindings::crypto_akcipher_sign(req.ptr))?;
        }

        Self::format_signature(&sign[0..32], &sign[32..])
    }

    fn key_schedule_for_handshake(&mut self) -> Result {
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
            &self.bytes,
            &mut client_hs_traffic_secret,
        )?;
        self.client_hs_traffic_secret
            .copy_from_slice(&client_hs_traffic_secret);

        let mut server_hs_traffic_secret = [0u8; 32];
        h.derive_secret(
            &self.hs_secret,
            b"s hs traffic",
            &self.bytes,
            &mut server_hs_traffic_secret,
        )?;
        self.server_hs_traffic_secret
            .copy_from_slice(&server_hs_traffic_secret);
        Ok(())
    }

    fn key_schedule_for_app(&mut self) -> Result {
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
            &self.bytes,
            &mut client_app_traffic_secret,
        )?;
        self.client_app_traffic_secret
            .copy_from_slice(&client_app_traffic_secret);

        let mut server_app_traffic_secret = [0u8; 32];
        h.derive_secret(
            &master_secret,
            b"s ap traffic",
            &self.bytes,
            &mut server_app_traffic_secret,
        )?;
        self.server_app_traffic_secret
            .copy_from_slice(&server_app_traffic_secret);

        Ok(())
    }
}

enum Message {
    ClientHello(ClientHelloPayload),
    ServerHello(ServerHelloPayload),
    EncryptedExtensions(EncryptedExtensionsPayload),
    ServerCert(ServerCertPayload),
    ServerCertVerify(ServerCertVerifyPayload),
    ServerFinished(FinishedPayload),
    ClientFinished(FinishedPayload),
}

impl core::fmt::Debug for Message {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            Message::ClientHello(_) => "ClientHello",
            Message::ServerHello(_) => "SereverHello",
            Message::EncryptedExtensions(_) => "EncryptedExtensions",
            Message::ServerCert(_) => "ServerCert",
            Message::ServerCertVerify(_) => "ServerCertVerify",
            Message::ServerFinished(_) => "ServerFinished",
            Message::ClientFinished(_) => "ClientFinished",
        };

        write!(f, "{}", name)?;
        Ok(())
    }
}

impl Message {
    fn new() -> Self {
        Message::ClientHello(ClientHelloPayload {})
    }

    fn handshake_type(&self) -> HandshakeType {
        match self {
            Message::ClientHello(_) => HandshakeType::ClientHello,
            Message::ServerHello(_) => HandshakeType::ServerHello,
            Message::EncryptedExtensions(_) => HandshakeType::EncryptedExtensions,
            Message::ServerCert(_) => HandshakeType::Certificate,
            Message::ServerCertVerify(_) => HandshakeType::CertificateVerify,
            Message::ServerFinished(_) => HandshakeType::Finished,
            Message::ClientFinished(_) => HandshakeType::Finished,
        }
    }

    fn content_type(&self) -> ContentType {
        match self {
            Message::ClientHello(_) | Message::ServerHello(_) => ContentType::Handshake,
            _ => ContentType::Application,
        }
    }

    fn is_writer(&self) -> bool {
        match self {
            Message::ClientHello(_) | Message::ClientFinished(_) => false,
            _ => true,
        }
    }

    fn decode(info: &mut CryptoInfo, buf: &mut Buf) -> Result<HandshakeType> {
        let t = HandshakeType::from(buf.get_u8()?);
        match t {
            HandshakeType::ClientHello => {
                ClientHelloPayload::decode(info, buf)?;
            }
            HandshakeType::Finished => {
                FinishedPayload::decode(info, buf)?;
            }
            _ => {}
        }
        Ok(t)
    }

    fn encode(&self, info: &mut CryptoInfo, bytes: &mut Buf) -> Result<usize> {
        match self {
            Message::ClientHello(a) => a.encode(info, bytes),
            Message::ServerHello(a) => a.encode(info, bytes),
            Message::EncryptedExtensions(a) => a.encode(info, bytes),
            Message::ServerCert(a) => a.encode(info, bytes),
            Message::ServerCertVerify(a) => a.encode(info, bytes),
            Message::ServerFinished(a) => a.encode(info, bytes),
            Message::ClientFinished(a) => a.encode(info, bytes),
        }
    }

    fn next(self) -> Option<Self> {
        match self {
            Message::ClientHello(_) => Some(Message::ServerHello(ServerHelloPayload {})),
            Message::ServerHello(_) => {
                Some(Message::EncryptedExtensions(EncryptedExtensionsPayload {}))
            }
            Message::EncryptedExtensions(_) => Some(Message::ServerCert(ServerCertPayload {})),
            Message::ServerCert(_) => Some(Message::ServerCertVerify(ServerCertVerifyPayload {})),
            Message::ServerCertVerify(_) => Some(Message::ServerFinished(FinishedPayload {})),
            Message::ServerFinished(_) => Some(Message::ClientFinished(FinishedPayload {})),
            Message::ClientFinished(_) => None,
        }
    }
}

struct ClientHelloPayload {}

impl ClientHelloPayload {
    fn encode(&self, _info: &CryptoInfo, _buf: &mut Buf) -> Result<usize> {
        Ok(0)
    }

    fn decode(info: &mut CryptoInfo, buf: &mut Buf) -> Result {
        let _len = buf.get_u24_be()?;
        let _ver = buf.get_u16_be()?;
        let mut random = [0; 32];
        for i in 0..32 {
            random[i] = buf.get_u8()?;
        }

        let sid_len = buf.get_u8()?;
        for _ in 0..sid_len {
            let _ = buf.get_u8()?;
        }
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
            if t == ExtensionType::KeyShare as u16 {
                let _ = buf.get_u16_be()?;
                let _group = buf.get_u16_be()?;
                let keylen = buf.get_u16_be()?;

                for i in 0..keylen {
                    info.client_pubkey[i as usize] = buf.get_u8()?;
                }
            } else {
                for _ in 0..l {
                    let _ = buf.get_u8()?;
                }
            }
            extension_len -= 4 + l;
        }
        Ok(())
    }
}

enum SignAlgo {
    EcdsaSecp256r1Sha256 = 0x0403,
}

enum CipherSuite {
    Aes128GcmSha256 = 0x1301,
    Aes256GcmSha384 = 0x1302,
    Chacha20Poly1305Sha256 = 0x1303,
    Aes128CcmSha256 = 0x1304,
    Aes128Ccm8Sha256 = 0x1305,
}

enum KeyExchangeAlgo {
    X25519 = 0x001d,
}

enum ExtensionType {
    ServerName = 0,
    StatusRequest = 5,
    SupportedGroups = 10,
    EcPointFormat = 11,
    SignatureAlgo = 13,
    CertificateTimestamp = 18,
    ExtendedMasterSecret = 23,
    SessionTicket = 35,
    SupportedVersion = 43,
    SpkKeyExchangeModes = 45,
    KeyShare = 51,
}

struct ExtensionKeyShare<'a> {
    pubkey: &'a [u8],
}

impl ExtensionKeyShare<'_> {
    fn encode(&self, buf: &mut Buf) -> Result {
        buf.put_u16_be(ExtensionType::KeyShare as u16)?;
        buf.put_u16_be(self.pubkey.len() as u16 + 4)?;
        buf.put_u16_be(KeyExchangeAlgo::X25519 as u16)?;
        buf.put_u16_be(self.pubkey.len() as u16)?;
        buf.put_slice(self.pubkey)
    }
}

struct ExtensionVersion {}

impl ExtensionVersion {
    fn encode(&self, buf: &mut Buf) -> Result {
        buf.put_u16_be(ExtensionType::SupportedVersion as u16)?;
        buf.put_u16_be(2)?;
        buf.put_u16_be(TLS_13_VERSION)
    }
}

struct ServerHelloPayload {}

impl ServerHelloPayload {
    fn encode(&self, info: &CryptoInfo, buf: &mut Buf) -> Result<usize> {
        let mut random = [0u8; 32];
        crypto::get_random_bytes(&mut random)?;

        buf.put_u8(HandshakeType::ServerHello as u8)?;
        // len: set later
        buf.put_u24_be(0)?;
        buf.put_u16_be(TLS_12_VERSION)?;

        buf.put_slice(&random)?;
        // session ID len
        buf.put_u8(0)?;
        buf.put_u16_be(CipherSuite::Aes128GcmSha256 as u16)?;
        // Compression Method: null
        buf.put_u8(0)?;

        // extention len: set later
        buf.put_u16_be(0)?;
        let ext_start = buf.get_pos();
        // extensions
        ExtensionKeyShare {
            pubkey: &info.pubkey,
        }
        .encode(buf)?;
        ExtensionVersion {}.encode(buf)?;

        let ext_end = buf.get_pos();

        buf.set_pos(ext_start - 2);
        buf.put_u16_be((ext_end - ext_start) as u16)?;
        buf.set_pos(1);
        buf.put_u24_be(ext_end as u32 - 4)?;

        Ok(ext_end)
    }
}

struct EncryptedExtensionsPayload {}

impl EncryptedExtensionsPayload {
    fn encode(&self, _info: &CryptoInfo, buf: &mut Buf) -> Result<usize> {
        buf.put_u8(HandshakeType::EncryptedExtensions as u8)?;
        buf.put_u24_be(6)?;
        buf.put_u16_be(4)?;
        buf.put_u16_be(0)?;
        buf.put_u16_be(0)?;

        Ok(buf.get_pos())
    }
}

struct ServerCertPayload {}

impl ServerCertPayload {
    fn encode(&self, info: &CryptoInfo, buf: &mut Buf) -> Result<usize> {
        let cert_len = info.server_cert.len() as u32;
        buf.put_u8(HandshakeType::Certificate as u8)?;
        buf.put_u24_be(cert_len + 9)?;
        buf.put_u8(0)?;
        buf.put_u24_be(cert_len + 5)?;
        buf.put_u24_be(cert_len)?;
        buf.put_slice(&info.server_cert)?;
        buf.put_u16_be(0)?;

        Ok(buf.get_pos())
    }
}

struct ServerCertVerifyPayload {}

impl ServerCertVerifyPayload {
    fn encode(&self, info: &mut CryptoInfo, buf: &mut Buf) -> Result<usize> {
        let sig_buf = info.generate_signature()?;
        buf.put_u8(HandshakeType::CertificateVerify as u8)?;
        buf.put_u24_be(sig_buf.as_ref().len() as u32 + 4)?;
        buf.put_u16_be(SignAlgo::EcdsaSecp256r1Sha256 as u16)?;
        buf.put_u16_be(sig_buf.as_ref().len() as u16)?;
        buf.put_slice(sig_buf.as_ref())?;

        Ok(buf.get_pos())
    }
}

struct FinishedPayload {}

impl FinishedPayload {
    fn decode(info: &mut CryptoInfo, buf: &mut Buf) -> Result {
        let len = buf.get_u24_be()?;
        for _ in 0..len {
            info.verify_data.try_push(buf.get_u8()?)?;
        }
        Ok(())
    }

    fn encode(&self, info: &CryptoInfo, buf: &mut Buf) -> Result<usize> {
        let verify = info.generate_verify()?;
        buf.put_u8(HandshakeType::Finished as u8)?;
        buf.put_u24_be(verify.len() as u32)?;
        buf.put_slice(&verify)?;

        Ok(buf.get_pos())
    }
}

enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    DecryptionFailed = 21,
    RecordOverflow = 22,
    DecompressionFailure = 30,
    HandshakeFailure = 40,
    NoCertificate = 41,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ExportRestriction = 60,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    NoRenegotiation = 100,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    CertificateUnobtainable = 111,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    BadCertificateHashVvalue = 114,
    UnknownPskIdentity = 115,
    CertificateRequired = 116,
    NoApplicationProtocol = 120,
}
