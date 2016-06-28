// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use std::cmp;
use std::io::{self,Read,Write,Seek,Cursor};
use std::str;
use byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt, NetworkEndian};
use time;
use rand;
use misc;
use misc::{PositionVec, Length16, Length24, OnMemoryRead};

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

impl CipherSuite {
    fn from_id(id: u16) -> Option<Self> {
        for &cs in CIPHER_SUITE_LIST.iter() {
            if id == (cs as u16) {
                return Some(cs);
            }
        }
        return None;
    }
    fn id(self) -> u16 {
        return self as u16;
    }
    fn parse(id: u16) -> io::Result<Self> {
        return Self::from_id(id).ok_or(
            io::Error::new(io::ErrorKind::InvalidData,
                           "Invalid CipherSuite"));
    }
    fn read_from(src: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let id = try!(src.read_u16::<NetworkEndian>());
        let ret = try!(Self::parse(id));
        return Ok(ret);
    }
    fn write_to(&self, dest: &mut Vec<u8>) -> io::Result<()> {
        try!(dest.write_u16::<NetworkEndian>(self.id()));
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

enum ConnectionEnd {
    Server, Client,
}

enum PRFAlgorithm {
    TlsPrfSha256,
}

enum BulkCipherAlgorithm {
    Null, RC4, TripleDES, AES,
}

enum CipherType {
    Stream, Block, AEAD,
}

enum MACAlgorithm {
    Null, HmacMd5, HmacSha1, HmacSha256, HmacSha384, HmacSha512,
}

struct SecurityParameters {
    entity: ConnectionEnd,
    prf_algorithm: PRFAlgorithm,
    bulk_cipher_algorithm: BulkCipherAlgorithm,
    cipher_type: CipherType,
    enc_key_length: u8,
    block_length: u8,
    fixed_iv_length: u8,
    record_iv_length: u8,
    mac_algorithm: MACAlgorithm,
    mac_length: u8,
    mac_key_length: u8,
    compression_method: CompressionMethod,
    master_secret: [u8; 48],
    client_random: TLSRandom,
    server_random: TLSRandom,
}

impl SecurityParameters {
    fn client_initial() -> SecurityParameters {
        return SecurityParameters {
            entity: ConnectionEnd::Client,
            prf_algorithm: PRFAlgorithm::TlsPrfSha256,
            bulk_cipher_algorithm: BulkCipherAlgorithm::Null,
            cipher_type: CipherType::Stream,
            enc_key_length: 0,
            block_length: 0,
            fixed_iv_length: 0,
            record_iv_length: 0,
            mac_algorithm: MACAlgorithm::Null,
            mac_length: 0,
            mac_key_length: 0,
            compression_method: CompressionMethod::Null,
            master_secret: [0; 48],
            client_random: TLSRandom::empty(),
            server_random: TLSRandom::empty(),
        };
    }
}

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
enum CipherSuite {
    TlsNullWithNullNull                     = 0x0000,
    TlsRsaWithNullMd5                       = 0x0001,
    TlsRsaWithNullSha                       = 0x0002,
    TlsRsaExportWithRc440Md5                = 0x0003,
    TlsRsaWithRc4128Md5                     = 0x0004,
    TlsRsaWithRc4128Sha                     = 0x0005,
    TlsRsaExportWithRc2Cbc40Md5             = 0x0006,
    TlsRsaWithIdeaCbcSha                    = 0x0007,
    TlsRsaExportWithDes40CbcSha             = 0x0008,
    TlsRsaWithDesCbcSha                     = 0x0009,
    TlsRsaWith3desEdeCbcSha                 = 0x000A,
    TlsDhDssExportWithDes40CbcSha           = 0x000B,
    TlsDhDssWithDesCbcSha                   = 0x000C,
    TlsDhDssWith3desEdeCbcSha               = 0x000D,
    TlsDhRsaExportWithDes40CbcSha           = 0x000E,
    TlsDhRsaWithDesCbcSha                   = 0x000F,
    TlsDhRsaWith3desEdeCbcSha               = 0x0010,
    TlsDheDssExportWithDes40CbcSha          = 0x0011,
    TlsDheDssWithDesCbcSha                  = 0x0012,
    TlsDheDssWith3desEdeCbcSha              = 0x0013,
    TlsDheRsaExportWithDes40CbcSha          = 0x0014,
    TlsDheRsaWithDesCbcSha                  = 0x0015,
    TlsDheRsaWith3desEdeCbcSha              = 0x0016,
    TlsDhAnonExportWithRc440Md5             = 0x0017,
    TlsDhAnonWithRc4128Md5                  = 0x0018,
    TlsDhAnonExportWithDes40CbcSha          = 0x0019,
    TlsDhAnonWithDesCbcSha                  = 0x001A,
    TlsDhAnonWith3desEdeCbcSha              = 0x001B,
    TlsKrb5WithDesCbcSha                    = 0x001E,
    TlsKrb5With3desEdeCbcSha                = 0x001F,
    TlsKrb5WithRc4128Sha                    = 0x0020,
    TlsKrb5WithIdeaCbcSha                   = 0x0021,
    TlsKrb5WithDesCbcMd5                    = 0x0022,
    TlsKrb5With3desEdeCbcMd5                = 0x0023,
    TlsKrb5WithRc4128Md5                    = 0x0024,
    TlsKrb5WithIdeaCbcMd5                   = 0x0025,
    TlsKrb5ExportWithDesCbc40Sha            = 0x0026,
    TlsKrb5ExportWithRc2Cbc40Sha            = 0x0027,
    TlsKrb5ExportWithRc440Sha               = 0x0028,
    TlsKrb5ExportWithDesCbc40Md5            = 0x0029,
    TlsKrb5ExportWithRc2Cbc40Md5            = 0x002A,
    TlsKrb5ExportWithRc440Md5               = 0x002B,
    TlsPskWithNullSha                       = 0x002C,
    TlsDhePskWithNullSha                    = 0x002D,
    TlsRsaPskWithNullSha                    = 0x002E,
    TlsRsaWithAes128CbcSha                  = 0x002F,
    TlsDhDssWithAes128CbcSha                = 0x0030,
    TlsDhRsaWithAes128CbcSha                = 0x0031,
    TlsDheDssWithAes128CbcSha               = 0x0032,
    TlsDheRsaWithAes128CbcSha               = 0x0033,
    TlsDhAnonWithAes128CbcSha               = 0x0034,
    TlsRsaWithAes256CbcSha                  = 0x0035,
    TlsDhDssWithAes256CbcSha                = 0x0036,
    TlsDhRsaWithAes256CbcSha                = 0x0037,
    TlsDheDssWithAes256CbcSha               = 0x0038,
    TlsDheRsaWithAes256CbcSha               = 0x0039,
    TlsDhAnonWithAes256CbcSha               = 0x003A,
    TlsRsaWithNullSha256                    = 0x003B,
    TlsRsaWithAes128CbcSha256               = 0x003C,
    TlsRsaWithAes256CbcSha256               = 0x003D,
    TlsDhDssWithAes128CbcSha256             = 0x003E,
    TlsDhRsaWithAes128CbcSha256             = 0x003F,
    TlsDheDssWithAes128CbcSha256            = 0x0040,
    TlsRsaWithCamellia128CbcSha             = 0x0041,
    TlsDhDssWithCamellia128CbcSha           = 0x0042,
    TlsDhRsaWithCamellia128CbcSha           = 0x0043,
    TlsDheDssWithCamellia128CbcSha          = 0x0044,
    TlsDheRsaWithCamellia128CbcSha          = 0x0045,
    TlsDhAnonWithCamellia128CbcSha          = 0x0046,
    TlsDheRsaWithAes128CbcSha256            = 0x0067,
    TlsDhDssWithAes256CbcSha256             = 0x0068,
    TlsDhRsaWithAes256CbcSha256             = 0x0069,
    TlsDheDssWithAes256CbcSha256            = 0x006A,
    TlsDheRsaWithAes256CbcSha256            = 0x006B,
    TlsDhAnonWithAes128CbcSha256            = 0x006C,
    TlsDhAnonWithAes256CbcSha256            = 0x006D,
    TlsRsaWithCamellia256CbcSha             = 0x0084,
    TlsDhDssWithCamellia256CbcSha           = 0x0085,
    TlsDhRsaWithCamellia256CbcSha           = 0x0086,
    TlsDheDssWithCamellia256CbcSha          = 0x0087,
    TlsDheRsaWithCamellia256CbcSha          = 0x0088,
    TlsDhAnonWithCamellia256CbcSha          = 0x0089,
    TlsPskWithRc4128Sha                     = 0x008A,
    TlsPskWith3desEdeCbcSha                 = 0x008B,
    TlsPskWithAes128CbcSha                  = 0x008C,
    TlsPskWithAes256CbcSha                  = 0x008D,
    TlsDhePskWithRc4128Sha                  = 0x008E,
    TlsDhePskWith3desEdeCbcSha              = 0x008F,
    TlsDhePskWithAes128CbcSha               = 0x0090,
    TlsDhePskWithAes256CbcSha               = 0x0091,
    TlsRsaPskWithRc4128Sha                  = 0x0092,
    TlsRsaPskWith3desEdeCbcSha              = 0x0093,
    TlsRsaPskWithAes128CbcSha               = 0x0094,
    TlsRsaPskWithAes256CbcSha               = 0x0095,
    TlsRsaWithSeedCbcSha                    = 0x0096,
    TlsDhDssWithSeedCbcSha                  = 0x0097,
    TlsDhRsaWithSeedCbcSha                  = 0x0098,
    TlsDheDssWithSeedCbcSha                 = 0x0099,
    TlsDheRsaWithSeedCbcSha                 = 0x009A,
    TlsDhAnonWithSeedCbcSha                 = 0x009B,
    TlsRsaWithAes128GcmSha256               = 0x009C,
    TlsRsaWithAes256GcmSha384               = 0x009D,
    TlsDheRsaWithAes128GcmSha256            = 0x009E,
    TlsDheRsaWithAes256GcmSha384            = 0x009F,
    TlsDhRsaWithAes128GcmSha256             = 0x00A0,
    TlsDhRsaWithAes256GcmSha384             = 0x00A1,
    TlsDheDssWithAes128GcmSha256            = 0x00A2,
    TlsDheDssWithAes256GcmSha384            = 0x00A3,
    TlsDhDssWithAes128GcmSha256             = 0x00A4,
    TlsDhDssWithAes256GcmSha384             = 0x00A5,
    TlsDhAnonWithAes128GcmSha256            = 0x00A6,
    TlsDhAnonWithAes256GcmSha384            = 0x00A7,
    TlsPskWithAes128GcmSha256               = 0x00A8,
    TlsPskWithAes256GcmSha384               = 0x00A9,
    TlsDhePskWithAes128GcmSha256            = 0x00AA,
    TlsDhePskWithAes256GcmSha384            = 0x00AB,
    TlsRsaPskWithAes128GcmSha256            = 0x00AC,
    TlsRsaPskWithAes256GcmSha384            = 0x00AD,
    TlsPskWithAes128CbcSha256               = 0x00AE,
    TlsPskWithAes256CbcSha384               = 0x00AF,
    TlsPskWithNullSha256                    = 0x00B0,
    TlsPskWithNullSha384                    = 0x00B1,
    TlsDhePskWithAes128CbcSha256            = 0x00B2,
    TlsDhePskWithAes256CbcSha384            = 0x00B3,
    TlsDhePskWithNullSha256                 = 0x00B4,
    TlsDhePskWithNullSha384                 = 0x00B5,
    TlsRsaPskWithAes128CbcSha256            = 0x00B6,
    TlsRsaPskWithAes256CbcSha384            = 0x00B7,
    TlsRsaPskWithNullSha256                 = 0x00B8,
    TlsRsaPskWithNullSha384                 = 0x00B9,
    TlsRsaWithCamellia128CbcSha256          = 0x00BA,
    TlsDhDssWithCamellia128CbcSha256        = 0x00BB,
    TlsDhRsaWithCamellia128CbcSha256        = 0x00BC,
    TlsDheDssWithCamellia128CbcSha256       = 0x00BD,
    TlsDheRsaWithCamellia128CbcSha256       = 0x00BE,
    TlsDhAnonWithCamellia128CbcSha256       = 0x00BF,
    TlsRsaWithCamellia256CbcSha256          = 0x00C0,
    TlsDhDssWithCamellia256CbcSha256        = 0x00C1,
    TlsDhRsaWithCamellia256CbcSha256        = 0x00C2,
    TlsDheDssWithCamellia256CbcSha256       = 0x00C3,
    TlsDheRsaWithCamellia256CbcSha256       = 0x00C4,
    TlsDhAnonWithCamellia256CbcSha256       = 0x00C5,
    TlsEmptyRenegotiationInfoScsv           = 0x00FF,
    TlsFallbackScsv                         = 0x5600,
    TlsEcdhEcdsaWithNullSha                 = 0xC001,
    TlsEcdhEcdsaWithRc4128Sha               = 0xC002,
    TlsEcdhEcdsaWith3desEdeCbcSha           = 0xC003,
    TlsEcdhEcdsaWithAes128CbcSha            = 0xC004,
    TlsEcdhEcdsaWithAes256CbcSha            = 0xC005,
    TlsEcdheEcdsaWithNullSha                = 0xC006,
    TlsEcdheEcdsaWithRc4128Sha              = 0xC007,
    TlsEcdheEcdsaWith3desEdeCbcSha          = 0xC008,
    TlsEcdheEcdsaWithAes128CbcSha           = 0xC009,
    TlsEcdheEcdsaWithAes256CbcSha           = 0xC00A,
    TlsEcdhRsaWithNullSha                   = 0xC00B,
    TlsEcdhRsaWithRc4128Sha                 = 0xC00C,
    TlsEcdhRsaWith3desEdeCbcSha             = 0xC00D,
    TlsEcdhRsaWithAes128CbcSha              = 0xC00E,
    TlsEcdhRsaWithAes256CbcSha              = 0xC00F,
    TlsEcdheRsaWithNullSha                  = 0xC010,
    TlsEcdheRsaWithRc4128Sha                = 0xC011,
    TlsEcdheRsaWith3desEdeCbcSha            = 0xC012,
    TlsEcdheRsaWithAes128CbcSha             = 0xC013,
    TlsEcdheRsaWithAes256CbcSha             = 0xC014,
    TlsEcdhAnonWithNullSha                  = 0xC015,
    TlsEcdhAnonWithRc4128Sha                = 0xC016,
    TlsEcdhAnonWith3desEdeCbcSha            = 0xC017,
    TlsEcdhAnonWithAes128CbcSha             = 0xC018,
    TlsEcdhAnonWithAes256CbcSha             = 0xC019,
    TlsSrpShaWith3desEdeCbcSha              = 0xC01A,
    TlsSrpShaRsaWith3desEdeCbcSha           = 0xC01B,
    TlsSrpShaDssWith3desEdeCbcSha           = 0xC01C,
    TlsSrpShaWithAes128CbcSha               = 0xC01D,
    TlsSrpShaRsaWithAes128CbcSha            = 0xC01E,
    TlsSrpShaDssWithAes128CbcSha            = 0xC01F,
    TlsSrpShaWithAes256CbcSha               = 0xC020,
    TlsSrpShaRsaWithAes256CbcSha            = 0xC021,
    TlsSrpShaDssWithAes256CbcSha            = 0xC022,
    TlsEcdheEcdsaWithAes128CbcSha256        = 0xC023,
    TlsEcdheEcdsaWithAes256CbcSha384        = 0xC024,
    TlsEcdhEcdsaWithAes128CbcSha256         = 0xC025,
    TlsEcdhEcdsaWithAes256CbcSha384         = 0xC026,
    TlsEcdheRsaWithAes128CbcSha256          = 0xC027,
    TlsEcdheRsaWithAes256CbcSha384          = 0xC028,
    TlsEcdhRsaWithAes128CbcSha256           = 0xC029,
    TlsEcdhRsaWithAes256CbcSha384           = 0xC02A,
    TlsEcdheEcdsaWithAes128GcmSha256        = 0xC02B,
    TlsEcdheEcdsaWithAes256GcmSha384        = 0xC02C,
    TlsEcdhEcdsaWithAes128GcmSha256         = 0xC02D,
    TlsEcdhEcdsaWithAes256GcmSha384         = 0xC02E,
    TlsEcdheRsaWithAes128GcmSha256          = 0xC02F,
    TlsEcdheRsaWithAes256GcmSha384          = 0xC030,
    TlsEcdhRsaWithAes128GcmSha256           = 0xC031,
    TlsEcdhRsaWithAes256GcmSha384           = 0xC032,
    TlsEcdhePskWithRc4128Sha                = 0xC033,
    TlsEcdhePskWith3desEdeCbcSha            = 0xC034,
    TlsEcdhePskWithAes128CbcSha             = 0xC035,
    TlsEcdhePskWithAes256CbcSha             = 0xC036,
    TlsEcdhePskWithAes128CbcSha256          = 0xC037,
    TlsEcdhePskWithAes256CbcSha384          = 0xC038,
    TlsEcdhePskWithNullSha                  = 0xC039,
    TlsEcdhePskWithNullSha256               = 0xC03A,
    TlsEcdhePskWithNullSha384               = 0xC03B,
    TlsRsaWithAria128CbcSha256              = 0xC03C,
    TlsRsaWithAria256CbcSha384              = 0xC03D,
    TlsDhDssWithAria128CbcSha256            = 0xC03E,
    TlsDhDssWithAria256CbcSha384            = 0xC03F,
    TlsDhRsaWithAria128CbcSha256            = 0xC040,
    TlsDhRsaWithAria256CbcSha384            = 0xC041,
    TlsDheDssWithAria128CbcSha256           = 0xC042,
    TlsDheDssWithAria256CbcSha384           = 0xC043,
    TlsDheRsaWithAria128CbcSha256           = 0xC044,
    TlsDheRsaWithAria256CbcSha384           = 0xC045,
    TlsDhAnonWithAria128CbcSha256           = 0xC046,
    TlsDhAnonWithAria256CbcSha384           = 0xC047,
    TlsEcdheEcdsaWithAria128CbcSha256       = 0xC048,
    TlsEcdheEcdsaWithAria256CbcSha384       = 0xC049,
    TlsEcdhEcdsaWithAria128CbcSha256        = 0xC04A,
    TlsEcdhEcdsaWithAria256CbcSha384        = 0xC04B,
    TlsEcdheRsaWithAria128CbcSha256         = 0xC04C,
    TlsEcdheRsaWithAria256CbcSha384         = 0xC04D,
    TlsEcdhRsaWithAria128CbcSha256          = 0xC04E,
    TlsEcdhRsaWithAria256CbcSha384          = 0xC04F,
    TlsRsaWithAria128GcmSha256              = 0xC050,
    TlsRsaWithAria256GcmSha384              = 0xC051,
    TlsDheRsaWithAria128GcmSha256           = 0xC052,
    TlsDheRsaWithAria256GcmSha384           = 0xC053,
    TlsDhRsaWithAria128GcmSha256            = 0xC054,
    TlsDhRsaWithAria256GcmSha384            = 0xC055,
    TlsDheDssWithAria128GcmSha256           = 0xC056,
    TlsDheDssWithAria256GcmSha384           = 0xC057,
    TlsDhDssWithAria128GcmSha256            = 0xC058,
    TlsDhDssWithAria256GcmSha384            = 0xC059,
    TlsDhAnonWithAria128GcmSha256           = 0xC05A,
    TlsDhAnonWithAria256GcmSha384           = 0xC05B,
    TlsEcdheEcdsaWithAria128GcmSha256       = 0xC05C,
    TlsEcdheEcdsaWithAria256GcmSha384       = 0xC05D,
    TlsEcdhEcdsaWithAria128GcmSha256        = 0xC05E,
    TlsEcdhEcdsaWithAria256GcmSha384        = 0xC05F,
    TlsEcdheRsaWithAria128GcmSha256         = 0xC060,
    TlsEcdheRsaWithAria256GcmSha384         = 0xC061,
    TlsEcdhRsaWithAria128GcmSha256          = 0xC062,
    TlsEcdhRsaWithAria256GcmSha384          = 0xC063,
    TlsPskWithAria128CbcSha256              = 0xC064,
    TlsPskWithAria256CbcSha384              = 0xC065,
    TlsDhePskWithAria128CbcSha256           = 0xC066,
    TlsDhePskWithAria256CbcSha384           = 0xC067,
    TlsRsaPskWithAria128CbcSha256           = 0xC068,
    TlsRsaPskWithAria256CbcSha384           = 0xC069,
    TlsPskWithAria128GcmSha256              = 0xC06A,
    TlsPskWithAria256GcmSha384              = 0xC06B,
    TlsDhePskWithAria128GcmSha256           = 0xC06C,
    TlsDhePskWithAria256GcmSha384           = 0xC06D,
    TlsRsaPskWithAria128GcmSha256           = 0xC06E,
    TlsRsaPskWithAria256GcmSha384           = 0xC06F,
    TlsEcdhePskWithAria128CbcSha256         = 0xC070,
    TlsEcdhePskWithAria256CbcSha384         = 0xC071,
    TlsEcdheEcdsaWithCamellia128CbcSha256   = 0xC072,
    TlsEcdheEcdsaWithCamellia256CbcSha384   = 0xC073,
    TlsEcdhEcdsaWithCamellia128CbcSha256    = 0xC074,
    TlsEcdhEcdsaWithCamellia256CbcSha384    = 0xC075,
    TlsEcdheRsaWithCamellia128CbcSha256     = 0xC076,
    TlsEcdheRsaWithCamellia256CbcSha384     = 0xC077,
    TlsEcdhRsaWithCamellia128CbcSha256      = 0xC078,
    TlsEcdhRsaWithCamellia256CbcSha384      = 0xC079,
    TlsRsaWithCamellia128GcmSha256          = 0xC07A,
    TlsRsaWithCamellia256GcmSha384          = 0xC07B,
    TlsDheRsaWithCamellia128GcmSha256       = 0xC07C,
    TlsDheRsaWithCamellia256GcmSha384       = 0xC07D,
    TlsDhRsaWithCamellia128GcmSha256        = 0xC07E,
    TlsDhRsaWithCamellia256GcmSha384        = 0xC07F,
    TlsDheDssWithCamellia128GcmSha256       = 0xC080,
    TlsDheDssWithCamellia256GcmSha384       = 0xC081,
    TlsDhDssWithCamellia128GcmSha256        = 0xC082,
    TlsDhDssWithCamellia256GcmSha384        = 0xC083,
    TlsDhAnonWithCamellia128GcmSha256       = 0xC084,
    TlsDhAnonWithCamellia256GcmSha384       = 0xC085,
    TlsEcdheEcdsaWithCamellia128GcmSha256   = 0xC086,
    TlsEcdheEcdsaWithCamellia256GcmSha384   = 0xC087,
    TlsEcdhEcdsaWithCamellia128GcmSha256    = 0xC088,
    TlsEcdhEcdsaWithCamellia256GcmSha384    = 0xC089,
    TlsEcdheRsaWithCamellia128GcmSha256     = 0xC08A,
    TlsEcdheRsaWithCamellia256GcmSha384     = 0xC08B,
    TlsEcdhRsaWithCamellia128GcmSha256      = 0xC08C,
    TlsEcdhRsaWithCamellia256GcmSha384      = 0xC08D,
    TlsPskWithCamellia128GcmSha256          = 0xC08E,
    TlsPskWithCamellia256GcmSha384          = 0xC08F,
    TlsDhePskWithCamellia128GcmSha256       = 0xC090,
    TlsDhePskWithCamellia256GcmSha384       = 0xC091,
    TlsRsaPskWithCamellia128GcmSha256       = 0xC092,
    TlsRsaPskWithCamellia256GcmSha384       = 0xC093,
    TlsPskWithCamellia128CbcSha256          = 0xC094,
    TlsPskWithCamellia256CbcSha384          = 0xC095,
    TlsDhePskWithCamellia128CbcSha256       = 0xC096,
    TlsDhePskWithCamellia256CbcSha384       = 0xC097,
    TlsRsaPskWithCamellia128CbcSha256       = 0xC098,
    TlsRsaPskWithCamellia256CbcSha384       = 0xC099,
    TlsEcdhePskWithCamellia128CbcSha256     = 0xC09A,
    TlsEcdhePskWithCamellia256CbcSha384     = 0xC09B,
    TlsRsaWithAes128Ccm                     = 0xC09C,
    TlsRsaWithAes256Ccm                     = 0xC09D,
    TlsDheRsaWithAes128Ccm                  = 0xC09E,
    TlsDheRsaWithAes256Ccm                  = 0xC09F,
    TlsRsaWithAes128Ccm8                    = 0xC0A0,
    TlsRsaWithAes256Ccm8                    = 0xC0A1,
    TlsDheRsaWithAes128Ccm8                 = 0xC0A2,
    TlsDheRsaWithAes256Ccm8                 = 0xC0A3,
    TlsPskWithAes128Ccm                     = 0xC0A4,
    TlsPskWithAes256Ccm                     = 0xC0A5,
    TlsDhePskWithAes128Ccm                  = 0xC0A6,
    TlsDhePskWithAes256Ccm                  = 0xC0A7,
    TlsPskWithAes128Ccm8                    = 0xC0A8,
    TlsPskWithAes256Ccm8                    = 0xC0A9,
    TlsPskDheWithAes128Ccm8                 = 0xC0AA,
    TlsPskDheWithAes256Ccm8                 = 0xC0AB,
    TlsEcdheEcdsaWithAes128Ccm              = 0xC0AC,
    TlsEcdheEcdsaWithAes256Ccm              = 0xC0AD,
    TlsEcdheEcdsaWithAes128Ccm8             = 0xC0AE,
    TlsEcdheEcdsaWithAes256Ccm8             = 0xC0AF,
    TlsEcdheRsaWithChacha20Poly1305Sha256   = 0xCCA8,
    TlsEcdheEcdsaWithChacha20Poly1305Sha256 = 0xCCA9,
    TlsDheRsaWithChacha20Poly1305Sha256     = 0xCCAA,
    TlsPskWithChacha20Poly1305Sha256        = 0xCCAB,
    TlsEcdhePskWithChacha20Poly1305Sha256   = 0xCCAC,
    TlsDhePskWithChacha20Poly1305Sha256     = 0xCCAD,
    TlsRsaPskWithChacha20Poly1305Sha256     = 0xCCAE,
}

const CIPHER_SUITE_LIST : [CipherSuite; 326] = [
    CipherSuite::TlsNullWithNullNull,
    CipherSuite::TlsRsaWithNullMd5,
    CipherSuite::TlsRsaWithNullSha,
    CipherSuite::TlsRsaExportWithRc440Md5,
    CipherSuite::TlsRsaWithRc4128Md5,
    CipherSuite::TlsRsaWithRc4128Sha,
    CipherSuite::TlsRsaExportWithRc2Cbc40Md5,
    CipherSuite::TlsRsaWithIdeaCbcSha,
    CipherSuite::TlsRsaExportWithDes40CbcSha,
    CipherSuite::TlsRsaWithDesCbcSha,
    CipherSuite::TlsRsaWith3desEdeCbcSha,
    CipherSuite::TlsDhDssExportWithDes40CbcSha,
    CipherSuite::TlsDhDssWithDesCbcSha,
    CipherSuite::TlsDhDssWith3desEdeCbcSha,
    CipherSuite::TlsDhRsaExportWithDes40CbcSha,
    CipherSuite::TlsDhRsaWithDesCbcSha,
    CipherSuite::TlsDhRsaWith3desEdeCbcSha,
    CipherSuite::TlsDheDssExportWithDes40CbcSha,
    CipherSuite::TlsDheDssWithDesCbcSha,
    CipherSuite::TlsDheDssWith3desEdeCbcSha,
    CipherSuite::TlsDheRsaExportWithDes40CbcSha,
    CipherSuite::TlsDheRsaWithDesCbcSha,
    CipherSuite::TlsDheRsaWith3desEdeCbcSha,
    CipherSuite::TlsDhAnonExportWithRc440Md5,
    CipherSuite::TlsDhAnonWithRc4128Md5,
    CipherSuite::TlsDhAnonExportWithDes40CbcSha,
    CipherSuite::TlsDhAnonWithDesCbcSha,
    CipherSuite::TlsDhAnonWith3desEdeCbcSha,
    CipherSuite::TlsKrb5WithDesCbcSha,
    CipherSuite::TlsKrb5With3desEdeCbcSha,
    CipherSuite::TlsKrb5WithRc4128Sha,
    CipherSuite::TlsKrb5WithIdeaCbcSha,
    CipherSuite::TlsKrb5WithDesCbcMd5,
    CipherSuite::TlsKrb5With3desEdeCbcMd5,
    CipherSuite::TlsKrb5WithRc4128Md5,
    CipherSuite::TlsKrb5WithIdeaCbcMd5,
    CipherSuite::TlsKrb5ExportWithDesCbc40Sha,
    CipherSuite::TlsKrb5ExportWithRc2Cbc40Sha,
    CipherSuite::TlsKrb5ExportWithRc440Sha,
    CipherSuite::TlsKrb5ExportWithDesCbc40Md5,
    CipherSuite::TlsKrb5ExportWithRc2Cbc40Md5,
    CipherSuite::TlsKrb5ExportWithRc440Md5,
    CipherSuite::TlsPskWithNullSha,
    CipherSuite::TlsDhePskWithNullSha,
    CipherSuite::TlsRsaPskWithNullSha,
    CipherSuite::TlsRsaWithAes128CbcSha,
    CipherSuite::TlsDhDssWithAes128CbcSha,
    CipherSuite::TlsDhRsaWithAes128CbcSha,
    CipherSuite::TlsDheDssWithAes128CbcSha,
    CipherSuite::TlsDheRsaWithAes128CbcSha,
    CipherSuite::TlsDhAnonWithAes128CbcSha,
    CipherSuite::TlsRsaWithAes256CbcSha,
    CipherSuite::TlsDhDssWithAes256CbcSha,
    CipherSuite::TlsDhRsaWithAes256CbcSha,
    CipherSuite::TlsDheDssWithAes256CbcSha,
    CipherSuite::TlsDheRsaWithAes256CbcSha,
    CipherSuite::TlsDhAnonWithAes256CbcSha,
    CipherSuite::TlsRsaWithNullSha256,
    CipherSuite::TlsRsaWithAes128CbcSha256,
    CipherSuite::TlsRsaWithAes256CbcSha256,
    CipherSuite::TlsDhDssWithAes128CbcSha256,
    CipherSuite::TlsDhRsaWithAes128CbcSha256,
    CipherSuite::TlsDheDssWithAes128CbcSha256,
    CipherSuite::TlsRsaWithCamellia128CbcSha,
    CipherSuite::TlsDhDssWithCamellia128CbcSha,
    CipherSuite::TlsDhRsaWithCamellia128CbcSha,
    CipherSuite::TlsDheDssWithCamellia128CbcSha,
    CipherSuite::TlsDheRsaWithCamellia128CbcSha,
    CipherSuite::TlsDhAnonWithCamellia128CbcSha,
    CipherSuite::TlsDheRsaWithAes128CbcSha256,
    CipherSuite::TlsDhDssWithAes256CbcSha256,
    CipherSuite::TlsDhRsaWithAes256CbcSha256,
    CipherSuite::TlsDheDssWithAes256CbcSha256,
    CipherSuite::TlsDheRsaWithAes256CbcSha256,
    CipherSuite::TlsDhAnonWithAes128CbcSha256,
    CipherSuite::TlsDhAnonWithAes256CbcSha256,
    CipherSuite::TlsRsaWithCamellia256CbcSha,
    CipherSuite::TlsDhDssWithCamellia256CbcSha,
    CipherSuite::TlsDhRsaWithCamellia256CbcSha,
    CipherSuite::TlsDheDssWithCamellia256CbcSha,
    CipherSuite::TlsDheRsaWithCamellia256CbcSha,
    CipherSuite::TlsDhAnonWithCamellia256CbcSha,
    CipherSuite::TlsPskWithRc4128Sha,
    CipherSuite::TlsPskWith3desEdeCbcSha,
    CipherSuite::TlsPskWithAes128CbcSha,
    CipherSuite::TlsPskWithAes256CbcSha,
    CipherSuite::TlsDhePskWithRc4128Sha,
    CipherSuite::TlsDhePskWith3desEdeCbcSha,
    CipherSuite::TlsDhePskWithAes128CbcSha,
    CipherSuite::TlsDhePskWithAes256CbcSha,
    CipherSuite::TlsRsaPskWithRc4128Sha,
    CipherSuite::TlsRsaPskWith3desEdeCbcSha,
    CipherSuite::TlsRsaPskWithAes128CbcSha,
    CipherSuite::TlsRsaPskWithAes256CbcSha,
    CipherSuite::TlsRsaWithSeedCbcSha,
    CipherSuite::TlsDhDssWithSeedCbcSha,
    CipherSuite::TlsDhRsaWithSeedCbcSha,
    CipherSuite::TlsDheDssWithSeedCbcSha,
    CipherSuite::TlsDheRsaWithSeedCbcSha,
    CipherSuite::TlsDhAnonWithSeedCbcSha,
    CipherSuite::TlsRsaWithAes128GcmSha256,
    CipherSuite::TlsRsaWithAes256GcmSha384,
    CipherSuite::TlsDheRsaWithAes128GcmSha256,
    CipherSuite::TlsDheRsaWithAes256GcmSha384,
    CipherSuite::TlsDhRsaWithAes128GcmSha256,
    CipherSuite::TlsDhRsaWithAes256GcmSha384,
    CipherSuite::TlsDheDssWithAes128GcmSha256,
    CipherSuite::TlsDheDssWithAes256GcmSha384,
    CipherSuite::TlsDhDssWithAes128GcmSha256,
    CipherSuite::TlsDhDssWithAes256GcmSha384,
    CipherSuite::TlsDhAnonWithAes128GcmSha256,
    CipherSuite::TlsDhAnonWithAes256GcmSha384,
    CipherSuite::TlsPskWithAes128GcmSha256,
    CipherSuite::TlsPskWithAes256GcmSha384,
    CipherSuite::TlsDhePskWithAes128GcmSha256,
    CipherSuite::TlsDhePskWithAes256GcmSha384,
    CipherSuite::TlsRsaPskWithAes128GcmSha256,
    CipherSuite::TlsRsaPskWithAes256GcmSha384,
    CipherSuite::TlsPskWithAes128CbcSha256,
    CipherSuite::TlsPskWithAes256CbcSha384,
    CipherSuite::TlsPskWithNullSha256,
    CipherSuite::TlsPskWithNullSha384,
    CipherSuite::TlsDhePskWithAes128CbcSha256,
    CipherSuite::TlsDhePskWithAes256CbcSha384,
    CipherSuite::TlsDhePskWithNullSha256,
    CipherSuite::TlsDhePskWithNullSha384,
    CipherSuite::TlsRsaPskWithAes128CbcSha256,
    CipherSuite::TlsRsaPskWithAes256CbcSha384,
    CipherSuite::TlsRsaPskWithNullSha256,
    CipherSuite::TlsRsaPskWithNullSha384,
    CipherSuite::TlsRsaWithCamellia128CbcSha256,
    CipherSuite::TlsDhDssWithCamellia128CbcSha256,
    CipherSuite::TlsDhRsaWithCamellia128CbcSha256,
    CipherSuite::TlsDheDssWithCamellia128CbcSha256,
    CipherSuite::TlsDheRsaWithCamellia128CbcSha256,
    CipherSuite::TlsDhAnonWithCamellia128CbcSha256,
    CipherSuite::TlsRsaWithCamellia256CbcSha256,
    CipherSuite::TlsDhDssWithCamellia256CbcSha256,
    CipherSuite::TlsDhRsaWithCamellia256CbcSha256,
    CipherSuite::TlsDheDssWithCamellia256CbcSha256,
    CipherSuite::TlsDheRsaWithCamellia256CbcSha256,
    CipherSuite::TlsDhAnonWithCamellia256CbcSha256,
    CipherSuite::TlsEmptyRenegotiationInfoScsv,
    CipherSuite::TlsFallbackScsv,
    CipherSuite::TlsEcdhEcdsaWithNullSha,
    CipherSuite::TlsEcdhEcdsaWithRc4128Sha,
    CipherSuite::TlsEcdhEcdsaWith3desEdeCbcSha,
    CipherSuite::TlsEcdhEcdsaWithAes128CbcSha,
    CipherSuite::TlsEcdhEcdsaWithAes256CbcSha,
    CipherSuite::TlsEcdheEcdsaWithNullSha,
    CipherSuite::TlsEcdheEcdsaWithRc4128Sha,
    CipherSuite::TlsEcdheEcdsaWith3desEdeCbcSha,
    CipherSuite::TlsEcdheEcdsaWithAes128CbcSha,
    CipherSuite::TlsEcdheEcdsaWithAes256CbcSha,
    CipherSuite::TlsEcdhRsaWithNullSha,
    CipherSuite::TlsEcdhRsaWithRc4128Sha,
    CipherSuite::TlsEcdhRsaWith3desEdeCbcSha,
    CipherSuite::TlsEcdhRsaWithAes128CbcSha,
    CipherSuite::TlsEcdhRsaWithAes256CbcSha,
    CipherSuite::TlsEcdheRsaWithNullSha,
    CipherSuite::TlsEcdheRsaWithRc4128Sha,
    CipherSuite::TlsEcdheRsaWith3desEdeCbcSha,
    CipherSuite::TlsEcdheRsaWithAes128CbcSha,
    CipherSuite::TlsEcdheRsaWithAes256CbcSha,
    CipherSuite::TlsEcdhAnonWithNullSha,
    CipherSuite::TlsEcdhAnonWithRc4128Sha,
    CipherSuite::TlsEcdhAnonWith3desEdeCbcSha,
    CipherSuite::TlsEcdhAnonWithAes128CbcSha,
    CipherSuite::TlsEcdhAnonWithAes256CbcSha,
    CipherSuite::TlsSrpShaWith3desEdeCbcSha,
    CipherSuite::TlsSrpShaRsaWith3desEdeCbcSha,
    CipherSuite::TlsSrpShaDssWith3desEdeCbcSha,
    CipherSuite::TlsSrpShaWithAes128CbcSha,
    CipherSuite::TlsSrpShaRsaWithAes128CbcSha,
    CipherSuite::TlsSrpShaDssWithAes128CbcSha,
    CipherSuite::TlsSrpShaWithAes256CbcSha,
    CipherSuite::TlsSrpShaRsaWithAes256CbcSha,
    CipherSuite::TlsSrpShaDssWithAes256CbcSha,
    CipherSuite::TlsEcdheEcdsaWithAes128CbcSha256,
    CipherSuite::TlsEcdheEcdsaWithAes256CbcSha384,
    CipherSuite::TlsEcdhEcdsaWithAes128CbcSha256,
    CipherSuite::TlsEcdhEcdsaWithAes256CbcSha384,
    CipherSuite::TlsEcdheRsaWithAes128CbcSha256,
    CipherSuite::TlsEcdheRsaWithAes256CbcSha384,
    CipherSuite::TlsEcdhRsaWithAes128CbcSha256,
    CipherSuite::TlsEcdhRsaWithAes256CbcSha384,
    CipherSuite::TlsEcdheEcdsaWithAes128GcmSha256,
    CipherSuite::TlsEcdheEcdsaWithAes256GcmSha384,
    CipherSuite::TlsEcdhEcdsaWithAes128GcmSha256,
    CipherSuite::TlsEcdhEcdsaWithAes256GcmSha384,
    CipherSuite::TlsEcdheRsaWithAes128GcmSha256,
    CipherSuite::TlsEcdheRsaWithAes256GcmSha384,
    CipherSuite::TlsEcdhRsaWithAes128GcmSha256,
    CipherSuite::TlsEcdhRsaWithAes256GcmSha384,
    CipherSuite::TlsEcdhePskWithRc4128Sha,
    CipherSuite::TlsEcdhePskWith3desEdeCbcSha,
    CipherSuite::TlsEcdhePskWithAes128CbcSha,
    CipherSuite::TlsEcdhePskWithAes256CbcSha,
    CipherSuite::TlsEcdhePskWithAes128CbcSha256,
    CipherSuite::TlsEcdhePskWithAes256CbcSha384,
    CipherSuite::TlsEcdhePskWithNullSha,
    CipherSuite::TlsEcdhePskWithNullSha256,
    CipherSuite::TlsEcdhePskWithNullSha384,
    CipherSuite::TlsRsaWithAria128CbcSha256,
    CipherSuite::TlsRsaWithAria256CbcSha384,
    CipherSuite::TlsDhDssWithAria128CbcSha256,
    CipherSuite::TlsDhDssWithAria256CbcSha384,
    CipherSuite::TlsDhRsaWithAria128CbcSha256,
    CipherSuite::TlsDhRsaWithAria256CbcSha384,
    CipherSuite::TlsDheDssWithAria128CbcSha256,
    CipherSuite::TlsDheDssWithAria256CbcSha384,
    CipherSuite::TlsDheRsaWithAria128CbcSha256,
    CipherSuite::TlsDheRsaWithAria256CbcSha384,
    CipherSuite::TlsDhAnonWithAria128CbcSha256,
    CipherSuite::TlsDhAnonWithAria256CbcSha384,
    CipherSuite::TlsEcdheEcdsaWithAria128CbcSha256,
    CipherSuite::TlsEcdheEcdsaWithAria256CbcSha384,
    CipherSuite::TlsEcdhEcdsaWithAria128CbcSha256,
    CipherSuite::TlsEcdhEcdsaWithAria256CbcSha384,
    CipherSuite::TlsEcdheRsaWithAria128CbcSha256,
    CipherSuite::TlsEcdheRsaWithAria256CbcSha384,
    CipherSuite::TlsEcdhRsaWithAria128CbcSha256,
    CipherSuite::TlsEcdhRsaWithAria256CbcSha384,
    CipherSuite::TlsRsaWithAria128GcmSha256,
    CipherSuite::TlsRsaWithAria256GcmSha384,
    CipherSuite::TlsDheRsaWithAria128GcmSha256,
    CipherSuite::TlsDheRsaWithAria256GcmSha384,
    CipherSuite::TlsDhRsaWithAria128GcmSha256,
    CipherSuite::TlsDhRsaWithAria256GcmSha384,
    CipherSuite::TlsDheDssWithAria128GcmSha256,
    CipherSuite::TlsDheDssWithAria256GcmSha384,
    CipherSuite::TlsDhDssWithAria128GcmSha256,
    CipherSuite::TlsDhDssWithAria256GcmSha384,
    CipherSuite::TlsDhAnonWithAria128GcmSha256,
    CipherSuite::TlsDhAnonWithAria256GcmSha384,
    CipherSuite::TlsEcdheEcdsaWithAria128GcmSha256,
    CipherSuite::TlsEcdheEcdsaWithAria256GcmSha384,
    CipherSuite::TlsEcdhEcdsaWithAria128GcmSha256,
    CipherSuite::TlsEcdhEcdsaWithAria256GcmSha384,
    CipherSuite::TlsEcdheRsaWithAria128GcmSha256,
    CipherSuite::TlsEcdheRsaWithAria256GcmSha384,
    CipherSuite::TlsEcdhRsaWithAria128GcmSha256,
    CipherSuite::TlsEcdhRsaWithAria256GcmSha384,
    CipherSuite::TlsPskWithAria128CbcSha256,
    CipherSuite::TlsPskWithAria256CbcSha384,
    CipherSuite::TlsDhePskWithAria128CbcSha256,
    CipherSuite::TlsDhePskWithAria256CbcSha384,
    CipherSuite::TlsRsaPskWithAria128CbcSha256,
    CipherSuite::TlsRsaPskWithAria256CbcSha384,
    CipherSuite::TlsPskWithAria128GcmSha256,
    CipherSuite::TlsPskWithAria256GcmSha384,
    CipherSuite::TlsDhePskWithAria128GcmSha256,
    CipherSuite::TlsDhePskWithAria256GcmSha384,
    CipherSuite::TlsRsaPskWithAria128GcmSha256,
    CipherSuite::TlsRsaPskWithAria256GcmSha384,
    CipherSuite::TlsEcdhePskWithAria128CbcSha256,
    CipherSuite::TlsEcdhePskWithAria256CbcSha384,
    CipherSuite::TlsEcdheEcdsaWithCamellia128CbcSha256,
    CipherSuite::TlsEcdheEcdsaWithCamellia256CbcSha384,
    CipherSuite::TlsEcdhEcdsaWithCamellia128CbcSha256,
    CipherSuite::TlsEcdhEcdsaWithCamellia256CbcSha384,
    CipherSuite::TlsEcdheRsaWithCamellia128CbcSha256,
    CipherSuite::TlsEcdheRsaWithCamellia256CbcSha384,
    CipherSuite::TlsEcdhRsaWithCamellia128CbcSha256,
    CipherSuite::TlsEcdhRsaWithCamellia256CbcSha384,
    CipherSuite::TlsRsaWithCamellia128GcmSha256,
    CipherSuite::TlsRsaWithCamellia256GcmSha384,
    CipherSuite::TlsDheRsaWithCamellia128GcmSha256,
    CipherSuite::TlsDheRsaWithCamellia256GcmSha384,
    CipherSuite::TlsDhRsaWithCamellia128GcmSha256,
    CipherSuite::TlsDhRsaWithCamellia256GcmSha384,
    CipherSuite::TlsDheDssWithCamellia128GcmSha256,
    CipherSuite::TlsDheDssWithCamellia256GcmSha384,
    CipherSuite::TlsDhDssWithCamellia128GcmSha256,
    CipherSuite::TlsDhDssWithCamellia256GcmSha384,
    CipherSuite::TlsDhAnonWithCamellia128GcmSha256,
    CipherSuite::TlsDhAnonWithCamellia256GcmSha384,
    CipherSuite::TlsEcdheEcdsaWithCamellia128GcmSha256,
    CipherSuite::TlsEcdheEcdsaWithCamellia256GcmSha384,
    CipherSuite::TlsEcdhEcdsaWithCamellia128GcmSha256,
    CipherSuite::TlsEcdhEcdsaWithCamellia256GcmSha384,
    CipherSuite::TlsEcdheRsaWithCamellia128GcmSha256,
    CipherSuite::TlsEcdheRsaWithCamellia256GcmSha384,
    CipherSuite::TlsEcdhRsaWithCamellia128GcmSha256,
    CipherSuite::TlsEcdhRsaWithCamellia256GcmSha384,
    CipherSuite::TlsPskWithCamellia128GcmSha256,
    CipherSuite::TlsPskWithCamellia256GcmSha384,
    CipherSuite::TlsDhePskWithCamellia128GcmSha256,
    CipherSuite::TlsDhePskWithCamellia256GcmSha384,
    CipherSuite::TlsRsaPskWithCamellia128GcmSha256,
    CipherSuite::TlsRsaPskWithCamellia256GcmSha384,
    CipherSuite::TlsPskWithCamellia128CbcSha256,
    CipherSuite::TlsPskWithCamellia256CbcSha384,
    CipherSuite::TlsDhePskWithCamellia128CbcSha256,
    CipherSuite::TlsDhePskWithCamellia256CbcSha384,
    CipherSuite::TlsRsaPskWithCamellia128CbcSha256,
    CipherSuite::TlsRsaPskWithCamellia256CbcSha384,
    CipherSuite::TlsEcdhePskWithCamellia128CbcSha256,
    CipherSuite::TlsEcdhePskWithCamellia256CbcSha384,
    CipherSuite::TlsRsaWithAes128Ccm,
    CipherSuite::TlsRsaWithAes256Ccm,
    CipherSuite::TlsDheRsaWithAes128Ccm,
    CipherSuite::TlsDheRsaWithAes256Ccm,
    CipherSuite::TlsRsaWithAes128Ccm8,
    CipherSuite::TlsRsaWithAes256Ccm8,
    CipherSuite::TlsDheRsaWithAes128Ccm8,
    CipherSuite::TlsDheRsaWithAes256Ccm8,
    CipherSuite::TlsPskWithAes128Ccm,
    CipherSuite::TlsPskWithAes256Ccm,
    CipherSuite::TlsDhePskWithAes128Ccm,
    CipherSuite::TlsDhePskWithAes256Ccm,
    CipherSuite::TlsPskWithAes128Ccm8,
    CipherSuite::TlsPskWithAes256Ccm8,
    CipherSuite::TlsPskDheWithAes128Ccm8,
    CipherSuite::TlsPskDheWithAes256Ccm8,
    CipherSuite::TlsEcdheEcdsaWithAes128Ccm,
    CipherSuite::TlsEcdheEcdsaWithAes256Ccm,
    CipherSuite::TlsEcdheEcdsaWithAes128Ccm8,
    CipherSuite::TlsEcdheEcdsaWithAes256Ccm8,
    CipherSuite::TlsEcdheRsaWithChacha20Poly1305Sha256,
    CipherSuite::TlsEcdheEcdsaWithChacha20Poly1305Sha256,
    CipherSuite::TlsDheRsaWithChacha20Poly1305Sha256,
    CipherSuite::TlsPskWithChacha20Poly1305Sha256,
    CipherSuite::TlsEcdhePskWithChacha20Poly1305Sha256,
    CipherSuite::TlsDhePskWithChacha20Poly1305Sha256,
    CipherSuite::TlsRsaPskWithChacha20Poly1305Sha256,
];

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
