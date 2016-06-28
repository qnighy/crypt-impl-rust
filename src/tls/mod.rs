// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

mod ciphersuites;

use std::cmp;
use std::io::{self,Read,Write,Seek,Cursor};
use std::str;
use byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt, NetworkEndian};
use time;
use rand;
use misc;
use misc::{PositionVec, Length16, Length24, OnMemoryRead};
use self::ciphersuites::CipherSuite;

pub struct TLSStream<S : Read + Write> {
    inner: S,
    pending_security_parameters: SecurityParameters,
    record_read_buf: Vec<u8>,
    record_write_buf: Vec<u8>,
    read_bufs: [Vec<u8>; 5],
    write_bufs: [Vec<u8>; 5],
}

impl<S: Read + Write> TLSStream<S> {
    pub fn new(inner: S) -> TLSStream<S> {
        let ret = TLSStream::<S> {
            inner: inner,
            pending_security_parameters:
                SecurityParameters::client_initial(),
            record_read_buf: Vec::with_capacity(2048),
            record_write_buf: Vec::with_capacity(2048),
            read_bufs: [
                Vec::with_capacity(10),
                Vec::with_capacity(10),
                Vec::with_capacity(1024),
                Vec::with_capacity(1024),
                Vec::with_capacity(10),
            ],
            write_bufs: [
                Vec::with_capacity(10),
                Vec::with_capacity(10),
                Vec::with_capacity(1024),
                Vec::with_capacity(1024),
                Vec::with_capacity(10),
            ],
        };
        return ret;
    }
    fn send_alert(&mut self, alert: Alert) -> io::Result<()> {
        try!(alert.write_to(&mut self.write_bufs[ContentType::Alert.idx()]));
        try!(self.flush(ContentType::Alert.idx()));
        try!(self.flush_record());
        return Ok(());
    }
    fn send_client_hello(&mut self) -> io::Result<()> {
        let client_random = TLSRandom::new();
        self.pending_security_parameters.client_random = client_random;
        let client_hello = HandshakeMessage::ClientHello {
            random: client_random,
            session_id: SessionID::empty(),
            cipher_suites: vec![
                CipherSuite::TlsEcdheEcdsaWithAes128GcmSha256,
                CipherSuite::TlsEcdheRsaWithAes128GcmSha256,
                CipherSuite::TlsEcdheEcdsaWithAes256GcmSha384,
                CipherSuite::TlsEcdheEcdsaWithChacha20Poly1305Sha256,
                CipherSuite::TlsEcdheRsaWithAes256GcmSha384,
                CipherSuite::TlsEcdheRsaWithChacha20Poly1305Sha256,
            ],
            compression_methods: vec![
                CompressionMethod::Null,
            ],
            extensions: vec![
                HelloExtension::ServerName(vec![
                    ServerName::HostName(b"qnighy.info".to_vec()),
                ]),
            ],
        };
        try!(client_hello.write_to(
            &mut self.write_bufs[ContentType::Handshake.idx()]));
        try!(self.flush(ContentType::Handshake.idx()));
        try!(self.flush_record());
        return Ok(());
    }
    fn flush_record(&mut self) -> io::Result<()> {
        let mut pos : usize = 0;
        let maxlen = self.record_write_buf.len();
        while pos < maxlen {
            // TODO: when num_wrote == 0
            let num_wrote = try!(
                self.inner.write(&self.record_write_buf[pos ..]));
            pos += num_wrote;
        }
        self.record_write_buf.clear();
        return Ok(());
    }
    fn flush(&mut self, content_idx: usize) -> io::Result<()> {
        assert!(content_idx < 4);
        let vec = &mut self.write_bufs[content_idx];
        let mut pos : usize = 0;
        let maxlen = vec.len();
        while pos < maxlen {
            // TODO: it's just plaintext!
            let len = cmp::min(maxlen - pos, MAX_CHUNK_LEN);
            self.record_write_buf.extend_from_slice(&[
                ContentType::from_idx(content_idx).id(),
                0x03, 0x03, (len >> 8) as u8, len as u8,
            ]);
            self.record_write_buf.extend(vec[pos .. pos + len].iter());
            pos += len;
        }
        vec.clear();
        return Ok(());
    }
    fn read_record(&mut self) -> io::Result<()> {
        self.record_read_buf.reserve(1024);
        let len = self.record_read_buf.len();
        let cap = self.record_read_buf.capacity();
        self.record_read_buf.resize(cap, 0);
        let num_read = try!(
            self.inner.read(&mut self.record_read_buf[len ..]));
        self.record_read_buf.resize(len + num_read, 0);
        return Ok(());
    }
    fn consume1_record(&mut self) -> io::Result<ContentType> {
        loop {
            let buflen = self.record_read_buf.len();
            let len =
                if buflen < 5 {
                    0
                } else {
                    NetworkEndian::read_u16(
                        &self.record_read_buf[3..5]) as usize
                };
            if buflen < 5 + len {
                try!(self.read_record());
            } else {
                let buf = &mut self.record_read_buf;
                let content_type = try!(ContentType::parse(buf[0]));
                let version_major = buf[1];
                let version_minor = buf[2];
                // TODO
                assert_eq!(version_major, 3);
                assert_eq!(version_minor, 3);
                {
                    let ciphertext = &buf[5 .. 5+len];
                    // TODO: it's just the ciphertext itself now!
                    let plaintext = ciphertext;
                    self.read_bufs[content_type.idx()]
                        .extend(plaintext.iter());
                }
                buf.drain(0 .. 5+len);
                return Ok(content_type);
            }
        }
    }
    fn consume_metadata(&mut self) -> io::Result<()> {
        loop {
            match try!(self.consume1_record()) {
                ContentType::ChangeCipherSpec => {
                    try!(self.consume_change_cipher_spec());
                },
                ContentType::Alert => {
                    try!(self.consume_alert());
                },
                ContentType::Handshake => {
                    try!(self.consume_handshake());
                },
                ContentType::ApplicationData => {
                    return Ok(());
                },
                ContentType::Heartbeat => {
                    try!(self.consume_heartbeat());
                },
            };
        }
    }
    fn consume_change_cipher_spec(&mut self) -> io::Result<()> {
        // TODO
        panic!("TODO: implement ChangeCipherSpec");
    }
    fn consume_alert(&mut self) -> io::Result<()> {
        // TODO
        panic!("TODO: implement Alert");
    }
    fn consume_handshake(&mut self) -> io::Result<()> {
        loop {
            let message : HandshakeMessage;
            {
                let vec = &mut self.read_bufs[ContentType::Handshake.idx()];
                {
                    if vec.len() < 4 {
                        return Ok(());
                    }
                    let length = {
                        let length0 = vec[1] as usize;
                        let length1 = vec[2] as usize;
                        let length2 = vec[3] as usize;
                        (length0 << 16) | (length1 << 8) | length2
                    };
                    if vec.len() < 4 + length {
                        return Ok(());
                    }
                }
                let position;
                {
                    let mut cursor = Cursor::<&[u8]>::new(&vec);
                    // TODO: error handling
                    message = try!(HandshakeMessage::read_from(&mut cursor));
                    position = cursor.position() as usize;
                }
                vec.drain(0 .. position);
            }
            // println!("{:?}", &message);
            match message {
                HandshakeMessage::ClientHello {
                    random,
                    session_id,
                    cipher_suites,
                    compression_methods,
                    extensions,
                } => {
                    // TODO
                    panic!("TODO: ClienHello");
                },
                HandshakeMessage::ServerHello {
                    server_version,
                    random,
                    session_id,
                    cipher_suite,
                    compression_method,
                    extensions,
                } => {
                    // TODO
                    assert_eq!(server_version, 0x0303);
                    self.pending_security_parameters.cipher_suite
                        = cipher_suite;
                    self.pending_security_parameters.compression_method
                        = compression_method;
                    self.pending_security_parameters.server_random
                        = random;
                    // println!("server_version = {:x}", server_version);
                },
                HandshakeMessage::Certificate(certificate_list) => {
                    // TODO
                    // println!("certificates:");
                    // for certificate in certificate_list.iter() {
                    //     println!("{:?}", certificate);
                    // }
                },
            };
        }
    }
    fn consume_heartbeat(&mut self) -> io::Result<()> {
        // TODO
        panic!("TODO: implement Heartbeat");
    }
}

const MAX_CHUNK_LEN : usize = 16384;
const CLIENT_HELLO : u8 = 0x01;
const SERVER_HELLO : u8 = 0x02;
const CERTIFICATE : u8 = 0x0B;
const EXTENSION_SERVER_NAME : u16 = 0;
const EXTENSION_MAX_FRAGMENT_LENGTH : u16 = 1;
const EXTENSION_CLIENT_CERTIFICATE_URL : u16 = 2;
const EXTENSION_TRUSTED_CA_KEYS : u16 = 3;
const EXTENSION_TRUNCATED_HMAC : u16 = 4;
const EXTENSION_STATUS_REQUEST : u16 = 5;
const EXTENSION_SIGNATURE_ALGORITHMS : u16 = 13;

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24,
}

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
struct ProtocolVersion {
    major: u8,
    minor: u8,
}

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
enum AlertLevel {
    Warning = 1, Fatal = 2,
}

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
enum AlertDescription {
    CloseNotify = 0, UnexpectedMessage = 10, BadRecordMac = 20,
    DecryptionFailed = 21, RecordOverflow = 22, DecompressionFailure = 30,
    HandshakeFailure = 40, NoCertificateRESERVED = 41, BadCertificate = 42,
    UnsupportedCertificate = 43, CertificateRevoked = 44,
    CertificateExpired = 45, CertificateUnknown = 46, IllegalParameter = 47,
    UnknownCA = 48, AccessDenied = 49, DecodeError = 50, DecryptError = 51,
    ExportRestrictionRESERVED = 60, ProtocolVersion = 70,
    InsufficientSecurity = 71, InternalError = 80, InappropriateFallback = 86,
    UserCanceled = 90, NoRenegotiation = 100, UnsupportedExtension = 110,
    CertificateUnobtainable = 111, UnrecognizedName = 112,
    BadCertificateStatusResponse = 113, BadCertificateHashValue = 114,
    UnknownPSKIdentity = 115,
}

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
struct Alert {
    level: AlertLevel,
    description: AlertDescription,
}

#[derive(Debug)]
enum HandshakeMessage {
    // HelloRequest,
    ClientHello {
        random: TLSRandom,
        session_id: SessionID,
        cipher_suites: Vec<CipherSuite>,
        compression_methods: Vec<CompressionMethod>,
        extensions: Vec<HelloExtension>,
    },
    ServerHello {
        server_version: u16, // TODO
        random: TLSRandom,
        session_id: SessionID,
        cipher_suite: CipherSuite,
        compression_method: CompressionMethod,
        extensions: Vec<HelloExtension>,
    },
    // HelloVerifyRequest,
    // NewSessionTicket,
    Certificate(Vec<Vec<u8>>),
    // ServerKeyExchange,
    // CertificateRequest,
    // ServerHelloDone,
    // CertificateVerify,
    // ClientKeyExchange,
    // Finished,
    // CertificateURL,
    // CertificateStatus,
    // SupplementalData,
}

#[derive(Clone, Copy, Debug)]
struct TLSRandom {
    bytes: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
struct SessionID {
    length: usize,
    bytes: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
enum CompressionMethod {
    Null = 0,
}

#[derive(Debug)]
enum HelloExtension {
    ServerName(Vec<ServerName>),
    // MaxFragmentLength,
    // ClientCertificateURL,
    // TrustedCAKeys,
    // TruncatedHMAC,
    // StatusRequest,
    // SignatureAlgorithms,
}

#[derive(Debug)]
enum ServerName {
    HostName(Vec<u8>),
}

impl<S: Read + Write> Drop for TLSStream<S> {
    fn drop(&mut self) {
        let _ = self.send_alert(Alert {
            level: AlertLevel::Fatal,
            description: AlertDescription::CloseNotify,
        });
    }
}

impl ContentType {
    fn from_idx(idx: usize) -> ContentType {
        return Self::from_id((idx + 20) as u8).unwrap();
    }
    fn idx(self) -> usize {
        return (self.id() - 20) as usize;
    }
    fn from_id(id: u8) -> Option<ContentType> {
        for &ct in [
            ContentType::ChangeCipherSpec,
            ContentType::Alert,
            ContentType::Handshake,
            ContentType::ApplicationData,
            ContentType::Heartbeat,
        ].iter() {
            if id == (ct as u8) {
                return Some(ct);
            }
        }
        return None;
    }
    fn id(self) -> u8 {
        return self as u8;
    }
    fn parse(id: u8) -> io::Result<Self> {
        return Self::from_id(id).ok_or(
            io::Error::new(io::ErrorKind::InvalidData,
                           "Invalid ContentType"));
    }
}

impl ProtocolVersion {
    fn parse(buf: &[u8]) -> io::Result<Self> {
        return Ok(ProtocolVersion {
            major: buf[0],
            minor: buf[1],
        });
    }
}

impl AlertLevel {
    fn from_id(id: u8) -> Option<AlertLevel> {
        let ret = match id {
            id if id == (AlertLevel::Warning as u8) => AlertLevel::Warning,
            id if id == (AlertLevel::Fatal as u8) => AlertLevel::Fatal,
            _ => { return None; },
        };
        return Some(ret);
    }
    fn id(self) -> u8 {
        return self as u8;
    }
    fn parse(id: u8) -> io::Result<AlertLevel> {
        return Self::from_id(id).ok_or(
            io::Error::new(io::ErrorKind::InvalidData, "Invalid AlertLevel"));
    }
}

impl AlertDescription {
    fn from_id(id: u8) -> Option<AlertDescription> {
        for &ad in [
            AlertDescription::CloseNotify,
            AlertDescription::UnexpectedMessage,
            AlertDescription::BadRecordMac,
            AlertDescription::DecryptionFailed,
            AlertDescription::RecordOverflow,
            AlertDescription::DecompressionFailure,
            AlertDescription::HandshakeFailure,
            AlertDescription::NoCertificateRESERVED,
            AlertDescription::BadCertificate,
            AlertDescription::UnsupportedCertificate,
            AlertDescription::CertificateRevoked,
            AlertDescription::CertificateExpired,
            AlertDescription::CertificateUnknown,
            AlertDescription::IllegalParameter,
            AlertDescription::UnknownCA,
            AlertDescription::AccessDenied,
            AlertDescription::DecodeError,
            AlertDescription::DecryptError,
            AlertDescription::ExportRestrictionRESERVED,
            AlertDescription::ProtocolVersion,
            AlertDescription::InsufficientSecurity,
            AlertDescription::InternalError,
            AlertDescription::InappropriateFallback,
            AlertDescription::UserCanceled,
            AlertDescription::NoRenegotiation,
            AlertDescription::UnsupportedExtension,
            AlertDescription::CertificateUnobtainable,
            AlertDescription::UnrecognizedName,
            AlertDescription::BadCertificateStatusResponse,
            AlertDescription::BadCertificateHashValue,
            AlertDescription::UnknownPSKIdentity,
        ].iter() {
            if id == (ad as u8) {
                return Some(ad);
            }
        }
        return None;
    }
    fn id(self) -> u8 {
        return self as u8;
    }
    fn parse(id: u8) -> io::Result<AlertDescription> {
        return Self::from_id(id).ok_or(
            io::Error::new(io::ErrorKind::InvalidData,
                           "Invalid AlertDescription"));
    }
}

impl Alert {
    fn read_from(src: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let level_id = try!(src.read_u8());
        let level = try!(AlertLevel::parse(level_id));
        let description_id = try!(src.read_u8());
        let description = try!(AlertDescription::parse(description_id));
        return Ok(Alert {
            level: level,
            description: description,
        });
    }
    fn write_to(&self, dest: &mut Vec<u8>) -> io::Result<()> {
        try!(dest.write_u8(self.level.id()));
        try!(dest.write_u8(self.description.id()));
        return Ok(());
    }
}

impl HandshakeMessage {
    fn read_from(src: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let handshake_type = try!(src.read_u8());
        let mut src_hs = Cursor::new(try!(src.read_buf_u24sized(0, 16777216)));
        let ret : HandshakeMessage;
        match handshake_type {
            CLIENT_HELLO => {
                // TODO
                panic!("TODO: read_from for ClientHello");
            },
            SERVER_HELLO => {
                let server_version = try!(src_hs.read_u16::<NetworkEndian>());
                let random = try!(TLSRandom::read_from(&mut src_hs));
                let session_id = try!(SessionID::read_from(&mut src_hs));
                let cipher_suite = try!(CipherSuite::read_from(&mut src_hs));
                let compression_method =
                    try!(CompressionMethod::read_from(&mut src_hs));
                let mut extensions = Vec::new();
                if src_hs.is_remaining() {
                    let mut src_ext =
                        Cursor::new(try!(src_hs.read_buf_u16sized(0, 65535)));
                    while src_hs.is_remaining() {
                        extensions.push(
                            try!(HelloExtension::read_from(&mut src_ext)));
                    }
                    src_ext.check_remaining();
                }
                ret = HandshakeMessage::ServerHello {
                    server_version: server_version,
                    random: random,
                    session_id: session_id,
                    cipher_suite: cipher_suite,
                    compression_method: compression_method,
                    extensions: extensions,
                };
            },
            CERTIFICATE => {
                let mut certificate_list = Vec::new();
                let mut src_certs =
                    Cursor::new(try!(src_hs.read_buf_u24sized(0, 16777215)));
                while src_certs.is_remaining() {
                    let certificate =
                        try!(src_certs.read_buf_u24sized(1, 16777215))
                        .to_vec();
                    certificate_list.push(certificate);
                }
                src_certs.check_remaining();
                ret = HandshakeMessage::Certificate(certificate_list);
            },
            t => {
                // TODO
                panic!("TODO: Unknown Handshake Type {}", t);
            }
        };
        try!(src_hs.check_remaining());
        return Ok(ret);
    }
    fn write_to(&self, dest: &mut Vec<u8>) -> io::Result<()> {
        match self {
            &HandshakeMessage::ClientHello {
                ref random,
                ref session_id,
                ref cipher_suites,
                ref compression_methods,
                ref extensions,
            } => {
                try!(dest.write_u8(CLIENT_HELLO));
                let mut dest = PositionVec::<Length24>::new(dest);
                try!(dest.write_all(&[0x03, 0x03]));
                try!(random.write_to(dest.get()));
                try!(session_id.write_to(dest.get()));
                try!(dest.write_u16::<NetworkEndian>(
                    (cipher_suites.len() * 2) as u16));
                for cipher_suite in cipher_suites.iter() {
                    try!(cipher_suite.write_to(dest.get()));
                }
                try!(dest.write_u8(compression_methods.len() as u8));
                for compression_method in compression_methods.iter() {
                    try!(compression_method.write_to(dest.get()));
                }
                if extensions.len() > 0 {
                    let mut dest = PositionVec::<Length16>::new(dest.get());
                    for extension in extensions {
                        try!(extension.write_to(dest.get()));
                    }
                    dest.finalize();
                }
                dest.finalize();
            }
            &HandshakeMessage::ServerHello {
                ref server_version,
                ref random,
                ref session_id,
                ref cipher_suite,
                ref compression_method,
                ref extensions,
            } => {
                // TODO
                panic!("TODO: write_to for ServerHello");
            },
            &HandshakeMessage::Certificate(ref certificate_list) => {
                // TODO
                panic!("TODO: write_to for Certificate");
            }
        };
        return Ok(());
    }
}

impl TLSRandom {
    fn new() -> TLSRandom {
        let time = time::now().to_timespec().sec as u32;
        let mut ret = TLSRandom {
            bytes: [0; 32],
        };
        NetworkEndian::write_u32(&mut ret.bytes[0..4], time);
        for i in 1..8 {
            NetworkEndian::write_u32(
                &mut ret.bytes[i*4 .. i*4+4], rand::random::<u32>());
        }
        return ret;
    }
    fn empty() -> TLSRandom {
        return TLSRandom {
            bytes: [0; 32],
        };
    }
    fn time(&self) -> u32 {
        return NetworkEndian::read_u32(&self.bytes[0..4]);
    }
    fn random_bytes<'a>(& 'a self) -> & 'a [u8] {
        return &self.bytes[4..32];
    }
    fn read_from(src: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let mut ret = TLSRandom {
            bytes: [0; 32],
        };
        try!(src.read_exact(&mut ret.bytes));
        return Ok(ret);
    }
    fn write_to(&self, dest: &mut Vec<u8>) -> io::Result<()> {
        try!(dest.write_all(&self.bytes));
        return Ok(());
    }
}

impl SessionID {
    fn empty() -> SessionID {
        return SessionID {
            length: 0,
            bytes: [0; 32],
        };
    }
    fn read_from(src: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let length = try!(src.read_u8()) as usize;
        let mut ret = SessionID {
            length: length,
            bytes: [0; 32],
        };
        try!(src.read_exact(&mut ret.bytes[0 .. length]));
        return Ok(ret);
    }
    fn write_to(&self, dest: &mut Vec<u8>) -> io::Result<()> {
        try!(dest.write_u8(self.length as u8));
        try!(dest.write_all(&self.bytes[0 .. self.length]));
        return Ok(());
    }
}

impl CompressionMethod {
    fn from_id(id: u8) -> Option<CompressionMethod> {
        for &cm in [
            CompressionMethod::Null,
        ].iter() {
            if id == (cm as u8) {
                return Some(cm);
            }
        }
        return None;
    }
    fn id(self) -> u8 {
        return self as u8;
    }
    fn read_from(src: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let id = try!(src.read_u8());
        let ret = try!(Self::from_id(id).ok_or(
            io::Error::new(io::ErrorKind::InvalidData,
                           "Invalid CompressionMethod")));
        return Ok(ret);
    }
    fn write_to(&self, dest: &mut Vec<u8>) -> io::Result<()> {
        try!(dest.write_u8(self.id()));
        return Ok(());
    }
}

impl HelloExtension {
    fn read_from(src: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let extension_type = try!(src.read_u16::<NetworkEndian>());
        let mut src_ext = Cursor::new(try!(src.read_buf_u16sized(0, 65535)));
        let ret : HelloExtension;
        match extension_type {
            EXTENSION_SERVER_NAME => {
                let mut server_names = Vec::new();
                if src_ext.is_remaining() {
                    let mut src_sn =
                        Cursor::new(try!(src_ext.read_buf_u16sized(1, 65535)));
                    while src_sn.is_remaining() {
                        server_names.push(
                            try!(ServerName::read_from(&mut src_sn)));
                    }
                    src_sn.check_remaining();
                }
                ret = HelloExtension::ServerName(server_names);
            },
            _ => {
                // TODO
                panic!("Unknown extension type");
            }
        };
        try!(src_ext.check_remaining());
        return Ok(ret);
    }
    fn write_to(&self, dest: &mut Vec<u8>) -> io::Result<()> {
        match self {
            &HelloExtension::ServerName(ref server_names) => {
                try!(dest.write_u16::<NetworkEndian>(EXTENSION_SERVER_NAME));
                let mut dest = PositionVec::<Length16>::new(dest);
                {
                    let mut dest = PositionVec::<Length16>::new(dest.get());
                    for server_name in server_names {
                        try!(server_name.write_to(dest.get()));
                    }
                    dest.finalize();
                }
                dest.finalize();
            }
        }
        return Ok(());
    }
}

impl ServerName {
    fn read_from(src: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let name_type = try!(src.read_u8());
        let ret : ServerName;
        match name_type {
            0x00 => {
                let length = try!(src.read_u16::<NetworkEndian>()) as usize;
                let mut host_name = vec![0; length];
                try!(src.read_exact(&mut host_name));
                ret = ServerName::HostName(host_name);
            },
            _ => {
                // TODO
                panic!("Unknown name type");
            }
        }
        return Ok(ret);
    }
    fn write_to(&self, dest: &mut Vec<u8>) -> io::Result<()> {
        match self {
            &ServerName::HostName(ref host_name) => {
                try!(dest.write_u8(0x00));
                try!(dest.write_u16::<NetworkEndian>(
                    host_name.len() as u16));
                try!(dest.write_all(host_name));
            }
        }
        return Ok(());
    }
}

// enum ConnectionEnd {
//     Server, Client,
// }

// enum PRFAlgorithm {
//     TlsPrfSha256,
// }

struct SecurityParameters {
    // entity: ConnectionEnd,
    // prf_algorithm: PRFAlgorithm,
    cipher_suite: CipherSuite,
    compression_method: CompressionMethod,
    // master_secret: [u8; 48],
    client_random: TLSRandom,
    server_random: TLSRandom,
}

impl SecurityParameters {
    fn client_initial() -> SecurityParameters {
        return SecurityParameters {
            // entity: ConnectionEnd::Client,
            // prf_algorithm: PRFAlgorithm::TlsPrfSha256,
            cipher_suite: CipherSuite::TlsNullWithNullNull,
            compression_method: CompressionMethod::Null,
            // master_secret: [0; 48],
            client_random: TLSRandom::empty(),
            server_random: TLSRandom::empty(),
        };
    }
}

#[test]
fn foo() {
    use std::net::TcpStream;
    let stream = TcpStream::connect("qnighy.info:443").unwrap();
    let mut stream = TLSStream::new(stream);
    stream.send_client_hello().unwrap();
    stream.consume_metadata().unwrap();
    panic!();
}

// TODO: dummy against deadcode detection
pub fn bar() {
    use std::net::TcpStream;
    let stream = TcpStream::connect("qnighy.info:443").unwrap();
    let mut stream = TLSStream::new(stream);
    stream.send_client_hello().unwrap();
    stream.consume_metadata().unwrap();
    panic!();
}
