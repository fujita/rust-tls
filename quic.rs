use core::ffi::c_void;
use kernel::bindings;
use kernel::crypto;
use kernel::error;
use kernel::prelude::*;
use kernel::print::call_printk_cont;
use kernel::sync::{Arc, UniqueArc};
use kernel::workqueue;
use kernel::Result;

use crate::buf::*;
use crate::tls::{self, HashAlgo, Hkdf};

pub(crate) const QUIC_VERSION: u32 = 0x1;

// same as MacOS
pub(crate) const IPPROTO_QUIC: u16 = 253;

const INET_CONNECTION_SOCK_SIZE: usize = core::mem::size_of::<bindings::inet_connection_sock>();

const CERT: &[u8; 349] = include_bytes!("certs/cert.der");
// The format in defined in RFC 5915
const PRIVKEY: &[u8; 121] = include_bytes!("certs/privkey.der");

static PROTO_NAME: &kernel::str::CStr = kernel::c_str!("QUIC");

#[derive(PartialEq)]
struct ConnectionId {
    bytes: [u8; Quic::MAX_CID_LEN],
    len: usize,
}

impl ConnectionId {
    fn new(bytes: &[u8]) -> Self {
        let mut cid = ConnectionId {
            bytes: [0; Quic::MAX_CID_LEN],
            len: core::cmp::min(bytes.len(), Quic::MAX_CID_LEN),
        };
        cid.bytes[0..cid.len].copy_from_slice(&bytes[0..cid.len]);

        cid
    }

    fn generate() -> Self {
        const ID: [u8; 8] = [0x09, 0xce, 0x18, 0xfd, 0xf4, 0x13, 0xc1, 0x0e];
        ConnectionId::new(&ID)
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

struct FrameInfo {
    frame_type: u8,
    length: usize, // total (header + payload)
    header_length: usize,
}

impl FrameInfo {
    fn new(frame_type: u8, length: usize, header_length: usize) -> Self {
        FrameInfo {
            frame_type,
            length,
            header_length,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum SpaceId {
    Initial,
    Handshake,
    Data,
}

struct PacketInfo {
    space: SpaceId,
    dcid: ConnectionId,
    scid: ConnectionId,
    len: usize, // total length (header + payload)
    pn_offset: usize,
}

impl PacketInfo {
    fn is_long(&self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Default)]
struct KeySet {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

impl KeySet {
    fn new(secret: &[u8]) -> Result<Self> {
        let context: [u8; 0] = [];
        let h = Hkdf::new(HashAlgo::SHA256);

        let mut key: [u8; 16] = [0; 16];
        h.expand_label(&secret, b"quic key", &context, &mut key)?;

        let mut iv: [u8; 12] = [0; 12];
        h.expand_label(&secret, b"quic iv", &context, &mut iv)?;

        let mut hp: [u8; 16] = [0; 16];
        h.expand_label(&secret, b"quic hp", &context, &mut hp)?;

        Ok(KeySet { key, iv, hp })
    }
}

struct SkBuff {
    ptr: *mut bindings::sk_buff,
}

impl SkBuff {
    fn new(ptr: *mut bindings::sk_buff) -> Self {
        SkBuff { ptr }
    }

    fn data_len(&self) -> usize {
        unsafe { (*self.ptr).len as usize }
    }

    fn bytes(&self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut((*self.ptr).data, self.data_len()) }
    }

    fn is_nonlinear(&self) -> bool {
        unsafe { bindings::skb_is_nonlinear(self.ptr) }
    }

    fn udp_source(&self) -> (u32, u16) {
        unsafe {
            let iph = bindings::ip_hdr(self.ptr);
            let udph = bindings::udp_hdr(self.ptr);
            let saddr: u32 = (*iph).saddr;
            let sport = (*udph).source;
            (saddr, sport)
        }
    }
}

impl Drop for SkBuff {
    fn drop(&mut self) {
        unsafe { bindings::consume_skb(self.ptr) }
    }
}

fn skb_recv_udp(sk: *mut bindings::sock) -> Option<SkBuff> {
    let mut err: i32 = 0;
    let skb = unsafe { bindings::skb_recv_udp(sk, bindings::MSG_DONTWAIT, &mut err) };
    if skb.is_null() {
        None
    } else {
        Some(SkBuff::new(skb))
    }
}

struct QuicWork {
    sock: *mut bindings::sock,
    work: workqueue::Work,
}

kernel::impl_self_work_adapter!(QuicWork, work, |w| {
    let qsk = unsafe { QuicSock::from_sock_ptr(w.sock) };
    unsafe {
        let _ = qsk.data_ready((*qsk.udp_socket).sk);
    }
});

struct QuicQueue {
    queue: workqueue::BoxedQueue,
    work: Arc<QuicWork>,
}

struct EndPoint {
    local_cid: ConnectionId,

    client_initial_keys: KeySet,
    server_initial_keys: KeySet,
    client_hs_keys: KeySet,
    server_hs_keys: KeySet,
    client_app_keys: KeySet,
    server_app_keys: KeySet,

    send_buf: *mut u8,
    context: tls::ServerContext,
    vec: *mut bindings::kvec,
    data_pn: u32,
}

impl Drop for EndPoint {
    fn drop(&mut self) {
        if !self.send_buf.is_null() {
            unsafe { bindings::kfree(self.send_buf as *mut core::ffi::c_void) }
        }
        if !self.vec.is_null() {
            unsafe { bindings::kfree(self.vec as *mut core::ffi::c_void) }
        }
    }
}

impl EndPoint {
    const SEND_BUF_SIZE: u64 = 8192;

    fn new(dcid: &ConnectionId, privkey: &[u8]) -> Result<Self> {
        let p = unsafe { bindings::__kmalloc(Self::SEND_BUF_SIZE as usize, bindings::GFP_KERNEL) };
        if p.is_null() {
            return Err(error::code::ENOMEM);
        }
        let vec = unsafe {
            bindings::__kmalloc(
                core::mem::size_of::<bindings::kvec>() * 8,
                bindings::GFP_KERNEL,
            ) as *mut bindings::kvec
        };
        let mut e = EndPoint {
            local_cid: ConnectionId::generate(),
            client_initial_keys: KeySet::default(),
            server_initial_keys: KeySet::default(),
            client_hs_keys: KeySet::default(),
            server_hs_keys: KeySet::default(),
            client_app_keys: KeySet::default(),
            server_app_keys: KeySet::default(),
            send_buf: p as *mut u8,
            context: tls::ServerContext::new(privkey)?,
            vec,
            data_pn: 0,
        };
        e.key_schedule_for_initial(dcid.bytes())?;

        Ok(e)
    }

    fn client_secrets(&self, space: SpaceId) -> Result<KeySet> {
        match space {
            SpaceId::Initial => Ok(self.client_initial_keys),
            SpaceId::Handshake => Ok(self.client_hs_keys),
            SpaceId::Data => Ok(self.client_app_keys),
        }
    }

    fn server_secrets(&self, space: SpaceId) -> Result<KeySet> {
        match space {
            SpaceId::Initial => Ok(self.server_initial_keys),
            SpaceId::Handshake => Ok(self.server_hs_keys),
            SpaceId::Data => Ok(self.server_app_keys),
        }
    }

    fn key_schedule_for_initial(&mut self, dcid: &[u8]) -> Result {
        let mut initial_secret = [0u8; 32];
        let h = Hkdf::new(HashAlgo::SHA256);
        h.extract(&Quic::INITIAL_SALT, dcid, &mut initial_secret)?;

        let f = |label: &[u8]| -> Result<[u8; 32]> {
            let context: [u8; 0] = [];
            let h = Hkdf::new(HashAlgo::SHA256);

            let mut secret: [u8; 32] = [0; 32];
            h.expand_label(&initial_secret, label, &context, &mut secret)?;
            Ok(secret)
        };

        self.client_initial_keys = KeySet::new(&f(b"client in")?)?;
        self.server_initial_keys = KeySet::new(&f(b"server in")?)?;
        Ok(())
    }

    fn key_schedule_for_handshake(&mut self) -> Result {
        self.context.key_schedule_for_handshake()?;
        self.client_hs_keys = KeySet::new(&self.context.client_handshake_secret())?;
        self.server_hs_keys = KeySet::new(&self.context.server_handshake_secret())?;
        Ok(())
    }

    fn key_schedule_for_app(&mut self) -> Result {
        self.context.key_schedule_for_app()?;
        self.client_app_keys = KeySet::new(&self.context.client_app_secret())?;
        self.server_app_keys = KeySet::new(&self.context.server_app_secret())?;
        Ok(())
    }
}

struct QuicSock {
    udp_socket: *mut bindings::socket,
    endpoints: Vec<EndPoint>,
    private_key: [u8; 32],
}

impl QuicSock {
    unsafe fn from_sock_ptr<'a>(sk: *mut bindings::sock) -> &'a mut Self {
        let ptr: *mut QuicSock = unsafe { sk.add(INET_CONNECTION_SOCK_SIZE) as *mut QuicSock };
        unsafe { &mut *ptr }
    }

    fn data_ready(&mut self, sk: *mut bindings::sock) -> Result {
        while let Some(skb) = skb_recv_udp(sk) {
            if skb.is_nonlinear() {
                pr_info!("FIXME: nonlinear skb");
                continue;
            }

            let mut offset: usize = 0;
            let (saddr, sport) = skb.udp_source();
            let skb_bytes = skb.bytes();

            while let Ok(pkt) = Quic::get_packet(&mut skb_bytes[offset..]) {
                pr_info!("pkt info: {:?} {} {}", pkt.space, pkt.len, pkt.pn_offset);

                let bytes = &mut skb_bytes[offset..offset + pkt.len];

                let idx = {
                    let len = self.endpoints.len();
                    let mut idx = len;
                    for i in 0..len {
                        if self.endpoints[i].local_cid == pkt.dcid {
                            idx = i;
                            break;
                        }
                    }
                    if idx == len {
                        self.endpoints
                            .try_push(EndPoint::new(&pkt.dcid, &self.private_key)?)?;
                    }
                    idx
                };

                let endpoint = &mut self.endpoints[idx];
                unsafe {
                    bindings::memset(
                        endpoint.send_buf as *mut core::ffi::c_void,
                        0,
                        EndPoint::SEND_BUF_SIZE,
                    );
                }

                let secrets = endpoint.client_secrets(pkt.space)?;
                let sample_offset = pkt.pn_offset + 4;
                let mask = Quic::header_protection_mask(
                    &bytes[sample_offset..sample_offset + Quic::SAMPLE_LEN],
                    &secrets.hp,
                )?;

                let (pn_len, packet_number) =
                    Quic::unprotect_header(pkt.is_long(), bytes, &mask, pkt.pn_offset)?;

                if pkt.space == SpaceId::Data {
                    endpoint.data_pn = packet_number;
                }

                Quic::decrypt_payload(
                    &secrets.key,
                    &secrets.iv,
                    packet_number,
                    &bytes[..pkt.pn_offset + pn_len],
                    &bytes[pkt.pn_offset + pn_len..],
                )?;

                let mut payload_offset = pkt.pn_offset + pn_len;
                let mut payload_len = pkt.len - payload_offset - 16; // AEAD tag length

                let mut vec_len = 0;
                while let Ok(frame) =
                    Quic::get_frame(&mut bytes[payload_offset..payload_offset + payload_len])
                {
                    pr_info!(
                        "frame info: {} {} {}",
                        frame.frame_type,
                        frame.length,
                        payload_len
                    );

                    if frame.length >= payload_len {
                        break;
                    }
                    if frame.frame_type == 0 {
                        // PADDING
                        break;
                    } else if frame.frame_type == 6 {
                        // CRYPTO
                        let _ = endpoint.context.write(
                            &mut bytes[payload_offset + frame.header_length
                                ..payload_offset + frame.length],
                        );
                        if pkt.space == SpaceId::Initial {
                            vec_len = 2;

                            let initial_pkt_len = Self::build_initial_rsp(
                                endpoint,
                                unsafe { core::slice::from_raw_parts_mut(endpoint.send_buf, 4096) },
                                &pkt,
                            )?;

                            endpoint.key_schedule_for_handshake()?;

                            let q = unsafe { (endpoint.send_buf as *mut u8).add(4096) };

                            Self::build_handshake_rsp(
                                endpoint,
                                unsafe { core::slice::from_raw_parts_mut(q, 4096) },
                                &pkt,
                                1200 - initial_pkt_len,
                            )?;

                            let mut vec = endpoint.vec;
                            unsafe {
                                (*vec).iov_base = endpoint.send_buf as *mut core::ffi::c_void;
                                (*vec).iov_len = initial_pkt_len;
                                vec = vec.add(1);
                                (*vec).iov_base = q as *mut core::ffi::c_void;
                                (*vec).iov_len = 1058;
                            }
                        } else if pkt.space == SpaceId::Handshake {
                            pr_info!("handshake completed");

                            let bytes =
                                unsafe { core::slice::from_raw_parts_mut(endpoint.send_buf, 4096) };
                            let (pn_offset, len) = {
                                let mut buf = Buf::new(bytes);
                                buf.put_u8(0x60)?;
                                buf.put_bytes(pkt.scid.bytes())?;
                                let pn_offset = buf.get_index();
                                buf.put_varlen_u8(0)?;
                                // packet number

                                buf.put_u8(0x1e)?;

                                buf.put_u8(0x02)?;
                                buf.put_u8(endpoint.data_pn as u8)?;
                                buf.put_u8(0)?;
                                buf.put_u8(0)?;
                                buf.put_u8(endpoint.data_pn as u8)?;
                                (pn_offset, buf.get_index())
                            };
                            let packet_number_len = 1;

                            Quic::encrypt_packet(
                                endpoint,
                                SpaceId::Data,
                                bytes,
                                0,
                                pn_offset,
                                packet_number_len,
                                len - (pn_offset + packet_number_len),
                            )?;

                            let mut vec = endpoint.vec;
                            unsafe {
                                (*vec).iov_base = endpoint.send_buf as *mut core::ffi::c_void;
                                (*vec).iov_len = len + 16;
                            }
                            vec_len = 1;
                        }
                    }
                    payload_len -= frame.length;
                    payload_offset += frame.length;
                }

                offset += pkt.len;

                if vec_len > 0 {
                    if Self::sendmsg(sk, saddr, sport, endpoint.vec, vec_len).is_err() {
                        // TODO: proper error handling
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn sendmsg(
        sk: *mut bindings::sock,
        addr: u32,
        port: u16,
        vec: *mut bindings::kvec,
        nr_vecs: usize,
    ) -> Result {
        let mut sin = bindings::sockaddr_in::default();
        let mut msg = bindings::msghdr::default();
        sin.sin_family = bindings::AF_INET as u16;
        sin.sin_port = port;
        sin.sin_addr = bindings::in_addr { s_addr: addr };
        msg.msg_name = &mut sin as *mut _ as *mut core::ffi::c_void;
        msg.msg_namelen = core::mem::size_of::<bindings::sockaddr_in>() as _;

        let mut len = 0;
        for i in 0..nr_vecs {
            unsafe { len += (*vec.add(i)).iov_len };
        }

        let r = unsafe { bindings::kernel_sendmsg((*sk).sk_socket, &mut msg, vec, nr_vecs, len) };
        if r == len as i32 {
            Ok(())
        } else {
            pr_info!("failed to send {}", r);
            Err(error::code::EIO)
        }
    }

    fn init(&mut self, udp_socket: *mut bindings::socket) -> Result {
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

        unsafe {
            self.udp_socket = udp_socket;
            for i in 0..self.private_key.len() {
                self.private_key[i] = PRIVKEY[i + 7];
            }
            core::ptr::write(&mut self.endpoints, Vec::try_with_capacity(0).unwrap());
        }

        Ok(())
    }

    fn build_initial_rsp(
        endpoint: &mut EndPoint,
        bytes: &mut [u8],
        pi: &PacketInfo,
    ) -> Result<usize> {
        let packet_number_len = 1;
        let packet_number = 0;

        let (pn_offset, mut payload_len) = {
            let mut buf = Buf::new(bytes);

            buf.put_u8(0x80)?;
            buf.put_u32_be(QUIC_VERSION)?;
            buf.put_u8(pi.scid.bytes().len() as u8)?;
            buf.put_bytes(pi.scid.bytes())?;
            buf.put_u8(endpoint.local_cid.bytes().len() as u8)?;
            buf.put_bytes(&endpoint.local_cid.bytes())?;
            // token len
            buf.put_u8(0)?;
            // length: set later
            buf.put_varlen_u16_be(0)?;
            let pn_offset = buf.get_index();
            // packet number
            buf.put_u8(packet_number)?;

            // ack
            buf.put_u8(2)?;
            buf.put_varlen_u8(0)?;
            buf.put_varlen_u8(0)?;
            buf.put_varlen_u8(0)?;
            buf.put_varlen_u8(0)?;

            // crypto
            buf.put_u8(6)?;
            buf.put_varlen_u8(0)?;
            // len: set later
            buf.put_varlen_u16_be(0)?;

            (pn_offset, buf.get_index())
        };
        let crypto_len_offset = payload_len - 2;

        let tls_len = tls::ServerHello::serialize(
            &mut bytes[payload_len..],
            &endpoint.context.generate_public_key()?,
        )?;
        endpoint
            .context
            .record(&bytes[payload_len..payload_len + tls_len])?;
        payload_len += tls_len;

        {
            let mut buf = Buf::new(bytes);
            buf.set_index(pn_offset - 2);
            buf.put_varlen_u16_be((payload_len - pn_offset + Quic::AEAD_TAG_LEN as usize) as u16)?;

            buf.set_index(crypto_len_offset);
            buf.put_varlen_u16_be(tls_len as u16)?;
        }

        Quic::encrypt_packet(
            endpoint,
            SpaceId::Initial,
            bytes,
            packet_number as u32,
            pn_offset,
            packet_number_len,
            payload_len - (pn_offset + packet_number_len),
        )?;
        Ok(payload_len + Quic::AEAD_TAG_LEN as usize)
    }

    fn build_handshake_rsp(
        endpoint: &mut EndPoint,
        bytes: &mut [u8],
        pi: &PacketInfo,
        mut packet_len: usize,
    ) -> Result {
        packet_len -= 1 + 4 + 1 + pi.scid.bytes().len() + 1 + endpoint.local_cid.bytes().len() + 2;
        let mut payload_len = 0;
        let (crypto_len_offset, pn_offset, tls_start) = {
            let mut buf = Buf::new(bytes);

            buf.put_u8(0xa0)?;
            buf.put_u32_be(1)?;

            buf.put_u8(pi.scid.bytes().len() as u8)?;
            buf.put_bytes(pi.scid.bytes())?;

            buf.put_u8(endpoint.local_cid.bytes().len() as u8)?;
            buf.put_bytes(&endpoint.local_cid.bytes())?;
            buf.put_varlen_u16_be(packet_len as u16)?;
            let pn_offset = buf.get_index();
            buf.put_u8(0)?;

            // crypto
            buf.put_u8(6)?;
            buf.put_varlen_u8(0)?;
            let len_offset = buf.get_index();
            // set later
            buf.put_varlen_u16_be(0)?;

            let tls_start = buf.get_index();

            (len_offset, pn_offset, tls_start)
        };
        let len = tls::EncryptedExtensions::serialize(
            &mut bytes[tls_start..],
            pi.dcid.bytes(),
            endpoint.local_cid.bytes(),
        )?;
        endpoint
            .context
            .record(&bytes[tls_start..tls_start + len])?;
        payload_len += len;
        let end = tls_start + len;

        let tls_start = end;
        let len = tls::Certificate::serialize(&mut bytes[tls_start..], CERT)?;
        endpoint
            .context
            .record(&bytes[tls_start..tls_start + len])?;
        payload_len += len;
        let end = tls_start + len;

        let tls_start = end;
        let len = tls::CertificateVerify::serialize(
            &mut bytes[tls_start..],
            &endpoint.context.signature()?.bytes(),
        )?;
        endpoint
            .context
            .record(&bytes[tls_start..tls_start + len])?;
        payload_len += len;
        let end = tls_start + len;

        let tls_start = end;
        let v = endpoint.context.generate_verify()?;
        let len = tls::Finished::serialize(&mut bytes[tls_start..], &v)?;
        endpoint
            .context
            .record(&bytes[tls_start..tls_start + len])?;
        payload_len += len;

        endpoint.key_schedule_for_app()?;
        {
            let mut buf = Buf::new(bytes);
            buf.set_index(crypto_len_offset);
            buf.put_varlen_u16_be(payload_len as u16)?;
        }
        let packet_number_len = 1;
        let padding_len = packet_len - 1 - (payload_len + 4) - Quic::AEAD_TAG_LEN as usize;

        Quic::encrypt_packet(
            endpoint,
            SpaceId::Handshake,
            bytes,
            0, // packet number
            pn_offset,
            packet_number_len,
            4 + (payload_len + padding_len) as usize,
        )
    }
}

pub(crate) struct Quic {}

impl Quic {
    const MAX_CID_LEN: usize = 160;
    const SAMPLE_LEN: usize = 16;
    const LOCAL_CID_LEN: usize = 8;
    const AEAD_TAG_LEN: u32 = 16;

    const INITIAL_SALT: [u8; 20] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];

    fn encrypt_packet(
        endpoint: &EndPoint,
        space: SpaceId,
        bytes: &mut [u8],
        packet_number: u32,
        pn_offset: usize,
        pn_len: usize,
        payload_len: usize,
    ) -> Result {
        let offset = pn_offset + pn_len;
        let header = &bytes[0..offset as usize];
        let payload = &bytes[offset..offset + payload_len];

        let key = endpoint.server_secrets(space)?;

        Quic::encrypt_payload(&key.key, &key.iv, packet_number, header, payload)?;

        let is_long = space == SpaceId::Initial || space == SpaceId::Handshake;

        Quic::protect_header(is_long, bytes, pn_offset, pn_len, &key.hp)
    }

    fn unprotect_header(
        is_long: bool,
        bytes: &[u8],
        mask: &[u8],
        pn_offset: usize,
    ) -> Result<(usize, u32)> {
        let mut flags = bytes[0];
        if is_long {
            flags ^= mask[0] & 0x0f;
        } else {
            flags ^= mask[0] & 0x1f;
        }

        let pn_len = ((flags & 0x03) + 1) as usize;

        if pn_len > 4 {
            return Err(error::code::EINVAL);
        }

        let mut packet_bytes = [0u8; 4];
        for i in 0..pn_len {
            packet_bytes[i] = bytes[pn_offset + i] ^ mask[1 + i]
        }

        let packet_number = {
            let mut buf = Buf::new(&mut packet_bytes);
            if pn_len == 1 {
                buf.get_u8().unwrap() as u32
            } else if pn_len == 2 {
                buf.get_u16_be().unwrap() as u32
            } else if pn_len == 4 {
                buf.get_u32_be().unwrap()
            } else {
                0
            }
        };

        Ok((pn_len, packet_number))
    }

    fn protect_header(
        is_long: bool,
        bytes: &mut [u8],
        pn_offset: usize,
        pn_len: usize,
        hp: &[u8],
    ) -> Result {
        let mask = Quic::header_protection_mask(&bytes[pn_offset + 4..pn_offset + 20], hp)?;

        if is_long {
            bytes[0] ^= mask[0] & 0x0f;
        } else {
            bytes[0] ^= mask[0] & 0x1f;
        }

        for i in 0..pn_len {
            bytes[pn_offset + i] ^= mask[1 + i];
        }

        Ok(())
    }

    fn header_protection_mask(sample: &[u8], key: &[u8]) -> Result<[u8; 5]> {
        let mut cipher = crypto::Skcipher::new(kernel::c_str!("ecb(aes)"), 0, 0)?;
        cipher.setkey(key)?;
        let mut mask: [u8; 5] = [0; 5];
        let mut rq = crypto::SkcipherRequest::new(&cipher)?;
        unsafe {
            let mut src: bindings::scatterlist = Default::default();
            bindings::sg_init_one(&mut src, sample.as_ptr() as _, 16);

            let mut dst: bindings::scatterlist = Default::default();
            let dst_data: [u8; 16] = [0; 16];
            bindings::sg_init_one(&mut dst, dst_data.as_ptr() as _, 16);

            bindings::skcipher_request_set_crypt(
                rq.ptr,
                &mut src,
                &mut dst,
                16,
                core::ptr::null_mut(),
            );
            rq.encrypt()?;
            for i in 0..mask.len() {
                mask[i] = dst_data[i];
            }
        }
        Ok(mask)
    }

    fn decrypt_payload(
        key: &[u8],
        iv: &[u8],
        packet_number: u32,
        header: &[u8],
        payload: &[u8],
    ) -> Result {
        let aead = crypto::Aead::new(kernel::c_str!("gcm(aes)"), 0, 0)?;
        let packet_number_bytes = packet_number.to_be_bytes();
        let mut nonce: [u8; 12] = [0; 12];
        for i in 0..packet_number_bytes.len() {
            nonce[nonce.len() - packet_number_bytes.len() + i] = packet_number_bytes[i];
        }
        for i in 0..nonce.len() {
            nonce[i] = nonce[i] ^ iv[i];
        }

        unsafe {
            bindings::crypto_aead_setkey(aead.ptr, key.as_ptr() as _, key.len() as u32);
            let mut sg: [bindings::scatterlist; 2] = [Default::default(); 2];
            bindings::sg_init_table(sg.as_mut_ptr(), 2);
            bindings::sg_set_buf(&mut sg[0], header.as_ptr() as _, header.len() as u32);
            bindings::sg_set_buf(&mut sg[1], payload.as_ptr() as _, payload.len() as u32);

            let req = bindings::aead_request_alloc(aead.ptr, bindings::GFP_KERNEL);
            bindings::aead_request_set_ad(req, header.len() as u32);
            bindings::aead_request_set_crypt(
                req,
                sg.as_mut_ptr(),
                sg.as_mut_ptr(),
                payload.len() as u32,
                nonce.as_mut_ptr(),
            );
            bindings::aead_request_set_callback(req, 0, None, core::ptr::null_mut());
            bindings::crypto_aead_decrypt(req);
        }
        Ok(())
    }

    fn encrypt_payload(
        key: &[u8],
        iv: &[u8],
        packet_number: u32,
        header: &[u8],
        payload: &[u8],
    ) -> Result {
        let aead = crypto::Aead::new(kernel::c_str!("gcm(aes)"), 0, 0)?;
        let packet_number_bytes = packet_number.to_be_bytes();

        let mut nonce: [u8; 12] = [0; 12];
        for i in 0..packet_number_bytes.len() {
            nonce[nonce.len() - packet_number_bytes.len() + i] = packet_number_bytes[i];
        }
        for i in 0..nonce.len() {
            nonce[i] = nonce[i] ^ iv[i];
        }

        unsafe {
            bindings::crypto_aead_setkey(aead.ptr, key.as_ptr() as _, key.len() as u32);
            let mut sg: [bindings::scatterlist; 2] = [Default::default(); 2];
            bindings::sg_init_table(sg.as_mut_ptr(), 2);
            bindings::sg_set_buf(&mut sg[0], header.as_ptr() as _, header.len() as u32);
            bindings::sg_set_buf(
                &mut sg[1],
                payload.as_ptr() as _,
                payload.len() as u32 + Self::AEAD_TAG_LEN,
            );

            let req = bindings::aead_request_alloc(aead.ptr, bindings::GFP_KERNEL);
            bindings::aead_request_set_ad(req, header.len() as u32);
            bindings::aead_request_set_crypt(
                req,
                sg.as_mut_ptr(),
                sg.as_mut_ptr(),
                payload.len() as u32,
                nonce.as_mut_ptr(),
            );
            bindings::aead_request_set_callback(req, 0, None, core::ptr::null_mut());
            let _ = bindings::crypto_aead_encrypt(req);
        }
        Ok(())
    }

    fn get_packet(bytes: &mut [u8]) -> Result<PacketInfo> {
        let mut buf = Buf::new(bytes);

        let flags = buf.get_u8()?;

        let is_long = flags >> 7 == 1;
        let space = if is_long {
            match flags >> 4 & 0x3 {
                0 => SpaceId::Initial,
                2 => SpaceId::Handshake,
                _ => SpaceId::Data,
            }
        } else {
            SpaceId::Data
        };

        let mut dcid = [0; Quic::MAX_CID_LEN];
        let dcid_len = if is_long {
            let _version = buf.get_u32_be()?;
            buf.get_u8()?
        } else {
            Quic::LOCAL_CID_LEN as u8
        };
        buf.get_bytes(&mut dcid, dcid_len as usize)?;

        if is_long {
            let scid_len = buf.get_u8()?;
            let mut scid = [0; Quic::MAX_CID_LEN];
            buf.get_bytes(&mut scid, scid_len as usize)?;

            if space == SpaceId::Initial {
                let token_len = buf.get_u8()?;
                buf.set_index(buf.get_index() + token_len as usize);
            }
            let length = buf.get_varlen_be()?;
            let pn_offset = buf.get_index();

            Ok(PacketInfo {
                space,
                scid: ConnectionId::new(&scid[0..scid_len.into()]),
                dcid: ConnectionId::new(&dcid[0..dcid_len.into()]),
                len: pn_offset + length as usize,
                pn_offset,
            })
        } else {
            let pn_offset = buf.get_index();

            Ok(PacketInfo {
                space,
                scid: ConnectionId::new(&[0u8; 0]),
                dcid: ConnectionId::new(&dcid[0..dcid_len.into()]),
                len: bytes.len(),
                pn_offset,
            })
        }
    }

    fn get_frame(bytes: &mut [u8]) -> Result<FrameInfo> {
        let mut buf = Buf::new(bytes);
        let frame_type = buf.get_varlen_be()? as u8;
        match frame_type {
            // PADDING
            0 => Ok(FrameInfo::new(frame_type, 0, 0)),
            // ACK
            2 => Ok(FrameInfo::new(frame_type, 5, 5)),
            // ACK
            3 => {
                let _lagest = buf.get_varlen_be()?;
                let _delay = buf.get_varlen_be()?;
                let range_count = buf.get_varlen_be()?;
                let _first = buf.get_varlen_be()?;
                for _ in 0..range_count {
                    let _ = buf.get_varlen_be()?;
                    let _ = buf.get_varlen_be()?;
                }
                let _ = buf.get_varlen_be()?;
                let _ = buf.get_varlen_be()?;
                let _ = buf.get_varlen_be()?;
                Ok(FrameInfo::new(frame_type, buf.get_index(), 0))
            }
            // CRYPTO
            6 => {
                let _offset = buf.get_varlen_be()?;
                let length = buf.get_varlen_be()?;
                Ok(FrameInfo::new(
                    frame_type,
                    buf.get_index() + length as usize,
                    buf.get_index(),
                ))
            }
            8..=0xf => {
                let _id = buf.get_varlen_be()?;
                let len = buf.get_varlen_be()?;

                for i in 0..len as usize {
                    if i == 0 {
                        pr_info!("DATA: ");
                    }
                    call_printk_cont(format_args!("{:02X} ", buf.get_u8()?));
                }
                Ok(FrameInfo::new(frame_type, buf.get_index(), 0))
            }
            0x18 => {
                let _seq = buf.get_varlen_be()?;
                let _ = buf.get_varlen_be()?;
                let len = buf.get_u8()?;
                for _ in 0..len {
                    _ = buf.get_u8()?;
                }
                for _ in 0..128 / 8 {
                    _ = buf.get_u8()?;
                }
                Ok(FrameInfo::new(frame_type, buf.get_index(), 0))
            }
            _ => Err(error::code::EIO),
        }
    }

    unsafe extern "C" fn data_ready(sk: *mut bindings::sock) {
        unsafe {
            bindings::read_lock_bh(&mut (*sk).sk_callback_lock);
            let q: Box<QuicQueue> = Box::from_raw((*sk).sk_user_data as *mut QuicQueue);
            q.queue.enqueue(q.work.clone());
            (*sk).sk_user_data = Box::into_raw(q) as *mut c_void;
            bindings::read_unlock_bh(&mut (*sk).sk_callback_lock);
        }
    }

    unsafe extern "C" fn init_sock(sk: *mut bindings::sock) -> i32 {
        let mut qsk = unsafe { QuicSock::from_sock_ptr(sk) };

        let mut socket = core::ptr::null_mut();
        unsafe {
            let r = bindings::sock_create_kern(
                &mut bindings::init_net,
                bindings::PF_INET as _,
                bindings::sock_type_SOCK_DGRAM as _,
                bindings::IPPROTO_UDP as _,
                &mut socket,
            );
            if r != 0 {
                qsk.udp_socket = core::ptr::null_mut();
                pr_info!("failed to create udp socket");
                return r;
            } else {
                (*(*socket).sk).sk_data_ready = Some(Quic::data_ready);

                QuicSock::init(qsk, socket).unwrap();

                let e = UniqueArc::try_new(QuicWork {
                    sock: sk,
                    work: workqueue::Work::new(),
                })
                .unwrap();
                kernel::init_work_item!(&e);

                let q = Box::try_new(QuicQueue {
                    queue: workqueue::Queue::try_new(fmt!("QUIC-{:x}", sk as usize)).unwrap(),
                    work: e.into(),
                })
                .unwrap();

                (*(*socket).sk).sk_user_data = Box::into_raw(q) as *mut c_void;
            }
        }

        0
    }

    unsafe extern "C" fn destroy(sk: *mut bindings::sock) {
        let qsk = unsafe { QuicSock::from_sock_ptr(sk) };

        if qsk.udp_socket.is_null() {
            unsafe { bindings::sock_release(qsk.udp_socket) }
        }
    }

    unsafe extern "C" fn bind(
        sock: *mut bindings::socket,
        addr: *mut bindings::sockaddr,
        addr_len: i32,
    ) -> i32 {
        let qsk = unsafe { QuicSock::from_sock_ptr((*sock).sk) };
        unsafe { bindings::kernel_bind(qsk.udp_socket, addr, addr_len) }
    }

    const PROTO_OPS: bindings::proto_ops = bindings::proto_ops {
        family: bindings::PF_INET as i32,
        owner: core::ptr::null_mut(),
        release: None,
        bind: Some(Quic::bind),
        connect: None,
        socketpair: None,
        accept: None,
        getname: None,
        poll: None,
        ioctl: None,
        compat_ioctl: None,
        gettstamp: None,
        listen: None,
        shutdown: None,
        setsockopt: None,
        getsockopt: None,
        show_fdinfo: None,
        sendmsg: None,
        recvmsg: None,
        mmap: None,
        sendpage: None,
        splice_read: None,
        sendpage_locked: None,
        set_peek_off: None,
        peek_len: None,
        read_sock: None,
        read_skb: None,
        sendmsg_locked: None,
        set_rcvlowat: None,
    };
}

pub(crate) fn build_proto() -> bindings::proto {
    let mut proto: bindings::proto = Default::default();

    for i in 0..PROTO_NAME.len() {
        proto.name[i] = PROTO_NAME[i] as i8;
    }

    proto.init = Some(Quic::init_sock);
    proto.destroy = Some(Quic::destroy);
    proto.obj_size = (INET_CONNECTION_SOCK_SIZE + core::mem::size_of::<QuicSock>()) as u32;

    proto
}

pub(crate) fn build_protosw() -> bindings::inet_protosw {
    let mut protosw: bindings::inet_protosw = Default::default();

    protosw.protocol = IPPROTO_QUIC;
    protosw.type_ = bindings::sock_type_SOCK_STREAM as u16;
    protosw.flags = bindings::INET_PROTOSW_ICSK as u8;
    protosw.ops = &Quic::PROTO_OPS;
    protosw
}
