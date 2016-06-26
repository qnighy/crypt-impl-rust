// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

extern crate byteorder;
extern crate time;
extern crate rand;

use misc::{LengthMarkR16, LengthMarkR24, LengthMarkW16, LengthMarkW24};
use std::cmp;
use std::io::{self,Read,Write,Seek,Cursor};
use std::str;
use self::byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt, NetworkEndian};

pub struct TLSStream<S : Read + Write> {
    inner: S,
    pending_security_parameters: SecurityParameters,
    record_read_buf: Vec<u8>,
    record_write_buf: Vec<u8>,
    read_bufs: [Cursor<Vec<u8>>; 5],
    write_bufs: [Cursor<Vec<u8>>; 5],
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
                Cursor::new(Vec::with_capacity(10)),
                Cursor::new(Vec::with_capacity(10)),
                Cursor::new(Vec::with_capacity(1024)),
                Cursor::new(Vec::with_capacity(1024)),
                Cursor::new(Vec::with_capacity(10)),
            ],
            write_bufs: [
                Cursor::new(Vec::with_capacity(10)),
                Cursor::new(Vec::with_capacity(10)),
                Cursor::new(Vec::with_capacity(1024)),
                Cursor::new(Vec::with_capacity(1024)),
                Cursor::new(Vec::with_capacity(10)),
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
                CipherSuite { id: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, },
                CipherSuite { id: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, },
                CipherSuite { id: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, },
                CipherSuite { id: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, },
                CipherSuite { id: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, },
                CipherSuite { id: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, },
                CipherSuite { id: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, },
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
        let cursor = &mut self.write_bufs[content_idx];
        cursor.set_position(0);
        let vec = cursor.get_mut();
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
                    self.read_bufs[content_type.idx()].get_mut()
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
                let cursor = &mut self.read_bufs[ContentType::Handshake.idx()];
                {
                    let vec = cursor.get_mut();
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
                message = try!(HandshakeMessage::read_from(cursor));
                let position = cursor.position() as usize;
                cursor.set_position(0);
                cursor.get_mut().drain(0 .. position);
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

#[derive(Debug)]
struct CipherSuite {
    id: u16,
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
    fn read_from<R:Read>(src: &mut R) -> io::Result<Self> {
        let level_id = try!(src.read_u8());
        let level = try!(AlertLevel::parse(level_id));
        let description_id = try!(src.read_u8());
        let description = try!(AlertDescription::parse(description_id));
        return Ok(Alert {
            level: level,
            description: description,
        });
    }
    fn write_to<W:Write>(&self, dest: &mut W) -> io::Result<()> {
        try!(dest.write_u8(self.level.id()));
        try!(dest.write_u8(self.description.id()));
        return Ok(());
    }
}

impl HandshakeMessage {
    fn read_from<R:Read+Seek>(src: &mut R) -> io::Result<Self> {
        let handshake_type = try!(src.read_u8());
        let handshake_mark = try!(LengthMarkR24::new(src));
        let ret : HandshakeMessage;
        match handshake_type {
            CLIENT_HELLO => {
                // TODO
                panic!("TODO: read_from for ClientHello");
            },
            SERVER_HELLO => {
                let server_version = try!(src.read_u16::<NetworkEndian>());
                let random = try!(TLSRandom::read_from(src));
                let session_id = try!(SessionID::read_from(src));
                let cipher_suite = try!(CipherSuite::read_from(src));
                let compression_method =
                    try!(CompressionMethod::read_from(src));
                let mut extensions = Vec::new();
                if try!(handshake_mark.is_remaining(src)) {
                    let extensions_mark = try!(LengthMarkR16::new(src));
                    while try!(extensions_mark.is_remaining(src)) {
                        extensions.push(try!(HelloExtension::read_from(src)));
                    }
                    try!(extensions_mark.check(src));
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
                let certificate_list_mark = try!(LengthMarkR24::new(src));
                while try!(certificate_list_mark.is_remaining(src)) {
                    let length = {
                        let length0 = try!(src.read_u8()) as usize;
                        let length1 = try!(src.read_u8()) as usize;
                        let length2 = try!(src.read_u8()) as usize;
                        (length0 << 16) | (length1 << 8) | length2
                    };
                    let mut certificate = vec![0; length];
                    try!(src.read_exact(&mut certificate));
                    certificate_list.push(certificate);
                }
                try!(certificate_list_mark.check(src));
                ret = HandshakeMessage::Certificate(certificate_list);
            },
            t => {
                // TODO
                panic!("TODO: Unknown Handshake Type {}", t);
            }
        };
        try!(handshake_mark.check(src));
        return Ok(ret);
    }
    fn write_to<W:Write+Seek>(&self, dest: &mut W) -> io::Result<()> {
        match self {
            &HandshakeMessage::ClientHello {
                ref random,
                ref session_id,
                ref cipher_suites,
                ref compression_methods,
                ref extensions,
            } => {
                try!(dest.write_u8(CLIENT_HELLO));
                let handshake_mark = try!(LengthMarkW24::new(dest));
                try!(dest.write_all(&[0x03, 0x03]));
                try!(random.write_to(dest));
                try!(session_id.write_to(dest));
                try!(dest.write_u16::<NetworkEndian>(
                    (cipher_suites.len() * 2) as u16));
                for cipher_suite in cipher_suites.iter() {
                    try!(cipher_suite.write_to(dest));
                }
                try!(dest.write_u8(compression_methods.len() as u8));
                for compression_method in compression_methods.iter() {
                    try!(compression_method.write_to(dest));
                }
                if extensions.len() > 0 {
                    let extensions_mark = try!(LengthMarkW16::new(dest));
                    for extension in extensions {
                        try!(extension.write_to(dest));
                    }
                    try!(extensions_mark.record(dest));
                }
                try!(handshake_mark.record(dest));
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
    fn read_from<R:Read>(src: &mut R) -> io::Result<Self> {
        let mut ret = TLSRandom {
            bytes: [0; 32],
        };
        try!(src.read_exact(&mut ret.bytes));
        return Ok(ret);
    }
    fn write_to<W:Write>(&self, dest: &mut W) -> io::Result<()> {
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
    fn read_from<R:Read>(src: &mut R) -> io::Result<Self> {
        let length = try!(src.read_u8()) as usize;
        let mut ret = SessionID {
            length: length,
            bytes: [0; 32],
        };
        try!(src.read_exact(&mut ret.bytes[0 .. length]));
        return Ok(ret);
    }
    fn write_to<W:Write>(&self, dest: &mut W) -> io::Result<()> {
        try!(dest.write_u8(self.length as u8));
        try!(dest.write_all(&self.bytes[0 .. self.length]));
        return Ok(());
    }
}

impl CipherSuite {
    fn read_from<R:Read>(src: &mut R) -> io::Result<Self> {
        let id = try!(src.read_u16::<NetworkEndian>());
        let ret = CipherSuite {
            id: id
        };
        return Ok(ret);
    }
    fn write_to<W:Write>(&self, dest: &mut W) -> io::Result<()> {
        try!(dest.write_u16::<NetworkEndian>(self.id));
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
    fn read_from<R:Read>(src: &mut R) -> io::Result<Self> {
        let id = try!(src.read_u8());
        let ret = try!(Self::from_id(id).ok_or(
            io::Error::new(io::ErrorKind::InvalidData,
                           "Invalid CompressionMethod")));
        return Ok(ret);
    }
    fn write_to<W:Write>(&self, dest: &mut W) -> io::Result<()> {
        try!(dest.write_u8(self.id()));
        return Ok(());
    }
}

impl HelloExtension {
    fn read_from<R:Read+Seek>(src: &mut R) -> io::Result<Self> {
        let extension_type = try!(src.read_u16::<NetworkEndian>());
        let extension_mark = try!(LengthMarkR16::new(src));
        let ret : HelloExtension;
        match extension_type {
            EXTENSION_SERVER_NAME => {
                let mut server_names = Vec::new();
                if try!(extension_mark.is_remaining(src)) {
                    let server_name_list_mark = try!(LengthMarkR16::new(src));
                    while try!(server_name_list_mark.is_remaining(src)) {
                        server_names.push(try!(ServerName::read_from(src)));
                    }
                    try!(server_name_list_mark.check(src));
                }
                ret = HelloExtension::ServerName(server_names);
            },
            _ => {
                // TODO
                panic!("Unknown extension type");
            }
        };
        try!(extension_mark.check(src));
        return Ok(ret);
    }
    fn write_to<W:Write+Seek>(&self, dest: &mut W) -> io::Result<()> {
        match self {
            &HelloExtension::ServerName(ref server_names) => {
                try!(dest.write_u16::<NetworkEndian>(EXTENSION_SERVER_NAME));
                let extension_mark = try!(LengthMarkW16::new(dest));
                let server_name_list_mark = try!(LengthMarkW16::new(dest));
                for server_name in server_names {
                    try!(server_name.write_to(dest));
                }
                try!(server_name_list_mark.record(dest));
                try!(extension_mark.record(dest));
            }
        }
        return Ok(());
    }
}

impl ServerName {
    fn read_from<R:Read>(src: &mut R) -> io::Result<Self> {
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
    fn write_to<W:Write>(&self, dest: &mut W) -> io::Result<()> {
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

pub const TLS_NULL_WITH_NULL_NULL                       : u16 = 0x0000;
pub const TLS_RSA_WITH_NULL_MD5                         : u16 = 0x0001;
pub const TLS_RSA_WITH_NULL_SHA                         : u16 = 0x0002;
pub const TLS_RSA_EXPORT_WITH_RC4_40_MD5                : u16 = 0x0003;
pub const TLS_RSA_WITH_RC4_128_MD5                      : u16 = 0x0004;
pub const TLS_RSA_WITH_RC4_128_SHA                      : u16 = 0x0005;
pub const TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5            : u16 = 0x0006;
pub const TLS_RSA_WITH_IDEA_CBC_SHA                     : u16 = 0x0007;
pub const TLS_RSA_EXPORT_WITH_DES40_CBC_SHA             : u16 = 0x0008;
pub const TLS_RSA_WITH_DES_CBC_SHA                      : u16 = 0x0009;
pub const TLS_RSA_WITH_3DES_EDE_CBC_SHA                 : u16 = 0x000A;
pub const TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA          : u16 = 0x000B;
pub const TLS_DH_DSS_WITH_DES_CBC_SHA                   : u16 = 0x000C;
pub const TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA              : u16 = 0x000D;
pub const TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA          : u16 = 0x000E;
pub const TLS_DH_RSA_WITH_DES_CBC_SHA                   : u16 = 0x000F;
pub const TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA              : u16 = 0x0010;
pub const TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA         : u16 = 0x0011;
pub const TLS_DHE_DSS_WITH_DES_CBC_SHA                  : u16 = 0x0012;
pub const TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA             : u16 = 0x0013;
pub const TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA         : u16 = 0x0014;
pub const TLS_DHE_RSA_WITH_DES_CBC_SHA                  : u16 = 0x0015;
pub const TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA             : u16 = 0x0016;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_EXPORT_WITH_RC4_40_MD5            : u16 = 0x0017;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_RC4_128_MD5                  : u16 = 0x0018;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA         : u16 = 0x0019;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_DES_CBC_SHA                  : u16 = 0x001A;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_3DES_EDE_CBC_SHA             : u16 = 0x001B;
pub const TLS_KRB5_WITH_DES_CBC_SHA                     : u16 = 0x001E;
pub const TLS_KRB5_WITH_3DES_EDE_CBC_SHA                : u16 = 0x001F;
pub const TLS_KRB5_WITH_RC4_128_SHA                     : u16 = 0x0020;
pub const TLS_KRB5_WITH_IDEA_CBC_SHA                    : u16 = 0x0021;
pub const TLS_KRB5_WITH_DES_CBC_MD5                     : u16 = 0x0022;
pub const TLS_KRB5_WITH_3DES_EDE_CBC_MD5                : u16 = 0x0023;
pub const TLS_KRB5_WITH_RC4_128_MD5                     : u16 = 0x0024;
pub const TLS_KRB5_WITH_IDEA_CBC_MD5                    : u16 = 0x0025;
pub const TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA           : u16 = 0x0026;
pub const TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA           : u16 = 0x0027;
pub const TLS_KRB5_EXPORT_WITH_RC4_40_SHA               : u16 = 0x0028;
pub const TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5           : u16 = 0x0029;
pub const TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5           : u16 = 0x002A;
pub const TLS_KRB5_EXPORT_WITH_RC4_40_MD5               : u16 = 0x002B;
pub const TLS_PSK_WITH_NULL_SHA                         : u16 = 0x002C;
pub const TLS_DHE_PSK_WITH_NULL_SHA                     : u16 = 0x002D;
pub const TLS_RSA_PSK_WITH_NULL_SHA                     : u16 = 0x002E;
pub const TLS_RSA_WITH_AES_128_CBC_SHA                  : u16 = 0x002F;
pub const TLS_DH_DSS_WITH_AES_128_CBC_SHA               : u16 = 0x0030;
pub const TLS_DH_RSA_WITH_AES_128_CBC_SHA               : u16 = 0x0031;
pub const TLS_DHE_DSS_WITH_AES_128_CBC_SHA              : u16 = 0x0032;
pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA              : u16 = 0x0033;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_AES_128_CBC_SHA              : u16 = 0x0034;
pub const TLS_RSA_WITH_AES_256_CBC_SHA                  : u16 = 0x0035;
pub const TLS_DH_DSS_WITH_AES_256_CBC_SHA               : u16 = 0x0036;
pub const TLS_DH_RSA_WITH_AES_256_CBC_SHA               : u16 = 0x0037;
pub const TLS_DHE_DSS_WITH_AES_256_CBC_SHA              : u16 = 0x0038;
pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA              : u16 = 0x0039;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_AES_256_CBC_SHA              : u16 = 0x003A;
pub const TLS_RSA_WITH_NULL_SHA256                      : u16 = 0x003B;
pub const TLS_RSA_WITH_AES_128_CBC_SHA256               : u16 = 0x003C;
pub const TLS_RSA_WITH_AES_256_CBC_SHA256               : u16 = 0x003D;
pub const TLS_DH_DSS_WITH_AES_128_CBC_SHA256            : u16 = 0x003E;
pub const TLS_DH_RSA_WITH_AES_128_CBC_SHA256            : u16 = 0x003F;
pub const TLS_DHE_DSS_WITH_AES_128_CBC_SHA256           : u16 = 0x0040;
pub const TLS_RSA_WITH_CAMELLIA_128_CBC_SHA             : u16 = 0x0041;
pub const TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA          : u16 = 0x0042;
pub const TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA          : u16 = 0x0043;
pub const TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA         : u16 = 0x0044;
pub const TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA         : u16 = 0x0045;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA         : u16 = 0x0046;
pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA256           : u16 = 0x0067;
pub const TLS_DH_DSS_WITH_AES_256_CBC_SHA256            : u16 = 0x0068;
pub const TLS_DH_RSA_WITH_AES_256_CBC_SHA256            : u16 = 0x0069;
pub const TLS_DHE_DSS_WITH_AES_256_CBC_SHA256           : u16 = 0x006A;
pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA256           : u16 = 0x006B;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_AES_128_CBC_SHA256           : u16 = 0x006C;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_AES_256_CBC_SHA256           : u16 = 0x006D;
pub const TLS_RSA_WITH_CAMELLIA_256_CBC_SHA             : u16 = 0x0084;
pub const TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA          : u16 = 0x0085;
pub const TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA          : u16 = 0x0086;
pub const TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA         : u16 = 0x0087;
pub const TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA         : u16 = 0x0088;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA         : u16 = 0x0089;
pub const TLS_PSK_WITH_RC4_128_SHA                      : u16 = 0x008A;
pub const TLS_PSK_WITH_3DES_EDE_CBC_SHA                 : u16 = 0x008B;
pub const TLS_PSK_WITH_AES_128_CBC_SHA                  : u16 = 0x008C;
pub const TLS_PSK_WITH_AES_256_CBC_SHA                  : u16 = 0x008D;
pub const TLS_DHE_PSK_WITH_RC4_128_SHA                  : u16 = 0x008E;
pub const TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA             : u16 = 0x008F;
pub const TLS_DHE_PSK_WITH_AES_128_CBC_SHA              : u16 = 0x0090;
pub const TLS_DHE_PSK_WITH_AES_256_CBC_SHA              : u16 = 0x0091;
pub const TLS_RSA_PSK_WITH_RC4_128_SHA                  : u16 = 0x0092;
pub const TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA             : u16 = 0x0093;
pub const TLS_RSA_PSK_WITH_AES_128_CBC_SHA              : u16 = 0x0094;
pub const TLS_RSA_PSK_WITH_AES_256_CBC_SHA              : u16 = 0x0095;
pub const TLS_RSA_WITH_SEED_CBC_SHA                     : u16 = 0x0096;
pub const TLS_DH_DSS_WITH_SEED_CBC_SHA                  : u16 = 0x0097;
pub const TLS_DH_RSA_WITH_SEED_CBC_SHA                  : u16 = 0x0098;
pub const TLS_DHE_DSS_WITH_SEED_CBC_SHA                 : u16 = 0x0099;
pub const TLS_DHE_RSA_WITH_SEED_CBC_SHA                 : u16 = 0x009A;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_SEED_CBC_SHA                 : u16 = 0x009B;
pub const TLS_RSA_WITH_AES_128_GCM_SHA256               : u16 = 0x009C;
pub const TLS_RSA_WITH_AES_256_GCM_SHA384               : u16 = 0x009D;
pub const TLS_DHE_RSA_WITH_AES_128_GCM_SHA256           : u16 = 0x009E;
pub const TLS_DHE_RSA_WITH_AES_256_GCM_SHA384           : u16 = 0x009F;
pub const TLS_DH_RSA_WITH_AES_128_GCM_SHA256            : u16 = 0x00A0;
pub const TLS_DH_RSA_WITH_AES_256_GCM_SHA384            : u16 = 0x00A1;
pub const TLS_DHE_DSS_WITH_AES_128_GCM_SHA256           : u16 = 0x00A2;
pub const TLS_DHE_DSS_WITH_AES_256_GCM_SHA384           : u16 = 0x00A3;
pub const TLS_DH_DSS_WITH_AES_128_GCM_SHA256            : u16 = 0x00A4;
pub const TLS_DH_DSS_WITH_AES_256_GCM_SHA384            : u16 = 0x00A5;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_AES_128_GCM_SHA256           : u16 = 0x00A6;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_AES_256_GCM_SHA384           : u16 = 0x00A7;
pub const TLS_PSK_WITH_AES_128_GCM_SHA256               : u16 = 0x00A8;
pub const TLS_PSK_WITH_AES_256_GCM_SHA384               : u16 = 0x00A9;
pub const TLS_DHE_PSK_WITH_AES_128_GCM_SHA256           : u16 = 0x00AA;
pub const TLS_DHE_PSK_WITH_AES_256_GCM_SHA384           : u16 = 0x00AB;
pub const TLS_RSA_PSK_WITH_AES_128_GCM_SHA256           : u16 = 0x00AC;
pub const TLS_RSA_PSK_WITH_AES_256_GCM_SHA384           : u16 = 0x00AD;
pub const TLS_PSK_WITH_AES_128_CBC_SHA256               : u16 = 0x00AE;
pub const TLS_PSK_WITH_AES_256_CBC_SHA384               : u16 = 0x00AF;
pub const TLS_PSK_WITH_NULL_SHA256                      : u16 = 0x00B0;
pub const TLS_PSK_WITH_NULL_SHA384                      : u16 = 0x00B1;
pub const TLS_DHE_PSK_WITH_AES_128_CBC_SHA256           : u16 = 0x00B2;
pub const TLS_DHE_PSK_WITH_AES_256_CBC_SHA384           : u16 = 0x00B3;
pub const TLS_DHE_PSK_WITH_NULL_SHA256                  : u16 = 0x00B4;
pub const TLS_DHE_PSK_WITH_NULL_SHA384                  : u16 = 0x00B5;
pub const TLS_RSA_PSK_WITH_AES_128_CBC_SHA256           : u16 = 0x00B6;
pub const TLS_RSA_PSK_WITH_AES_256_CBC_SHA384           : u16 = 0x00B7;
pub const TLS_RSA_PSK_WITH_NULL_SHA256                  : u16 = 0x00B8;
pub const TLS_RSA_PSK_WITH_NULL_SHA384                  : u16 = 0x00B9;
pub const TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256          : u16 = 0x00BA;
pub const TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256       : u16 = 0x00BB;
pub const TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256       : u16 = 0x00BC;
pub const TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256      : u16 = 0x00BD;
pub const TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256      : u16 = 0x00BE;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256      : u16 = 0x00BF;
pub const TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256          : u16 = 0x00C0;
pub const TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256       : u16 = 0x00C1;
pub const TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256       : u16 = 0x00C2;
pub const TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256      : u16 = 0x00C3;
pub const TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256      : u16 = 0x00C4;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256      : u16 = 0x00C5;
pub const TLS_EMPTY_RENEGOTIATION_INFO_SCSV             : u16 = 0x00FF;
pub const TLS_FALLBACK_SCSV                             : u16 = 0x5600;
pub const TLS_ECDH_ECDSA_WITH_NULL_SHA                  : u16 = 0xC001;
pub const TLS_ECDH_ECDSA_WITH_RC4_128_SHA               : u16 = 0xC002;
pub const TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA          : u16 = 0xC003;
pub const TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA           : u16 = 0xC004;
pub const TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA           : u16 = 0xC005;
pub const TLS_ECDHE_ECDSA_WITH_NULL_SHA                 : u16 = 0xC006;
pub const TLS_ECDHE_ECDSA_WITH_RC4_128_SHA              : u16 = 0xC007;
pub const TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA         : u16 = 0xC008;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          : u16 = 0xC009;
pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          : u16 = 0xC00A;
pub const TLS_ECDH_RSA_WITH_NULL_SHA                    : u16 = 0xC00B;
pub const TLS_ECDH_RSA_WITH_RC4_128_SHA                 : u16 = 0xC00C;
pub const TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA            : u16 = 0xC00D;
pub const TLS_ECDH_RSA_WITH_AES_128_CBC_SHA             : u16 = 0xC00E;
pub const TLS_ECDH_RSA_WITH_AES_256_CBC_SHA             : u16 = 0xC00F;
pub const TLS_ECDHE_RSA_WITH_NULL_SHA                   : u16 = 0xC010;
pub const TLS_ECDHE_RSA_WITH_RC4_128_SHA                : u16 = 0xC011;
pub const TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA           : u16 = 0xC012;
pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            : u16 = 0xC013;
pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            : u16 = 0xC014;
#[allow(non_upper_case_globals)]
pub const TLS_ECDH_anon_WITH_NULL_SHA                   : u16 = 0xC015;
#[allow(non_upper_case_globals)]
pub const TLS_ECDH_anon_WITH_RC4_128_SHA                : u16 = 0xC016;
#[allow(non_upper_case_globals)]
pub const TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA           : u16 = 0xC017;
#[allow(non_upper_case_globals)]
pub const TLS_ECDH_anon_WITH_AES_128_CBC_SHA            : u16 = 0xC018;
#[allow(non_upper_case_globals)]
pub const TLS_ECDH_anon_WITH_AES_256_CBC_SHA            : u16 = 0xC019;
pub const TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA             : u16 = 0xC01A;
pub const TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA         : u16 = 0xC01B;
pub const TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA         : u16 = 0xC01C;
pub const TLS_SRP_SHA_WITH_AES_128_CBC_SHA              : u16 = 0xC01D;
pub const TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA          : u16 = 0xC01E;
pub const TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA          : u16 = 0xC01F;
pub const TLS_SRP_SHA_WITH_AES_256_CBC_SHA              : u16 = 0xC020;
pub const TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA          : u16 = 0xC021;
pub const TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA          : u16 = 0xC022;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256       : u16 = 0xC023;
pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384       : u16 = 0xC024;
pub const TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256        : u16 = 0xC025;
pub const TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384        : u16 = 0xC026;
pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256         : u16 = 0xC027;
pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384         : u16 = 0xC028;
pub const TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256          : u16 = 0xC029;
pub const TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384          : u16 = 0xC02A;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       : u16 = 0xC02B;
pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       : u16 = 0xC02C;
pub const TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256        : u16 = 0xC02D;
pub const TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384        : u16 = 0xC02E;
pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         : u16 = 0xC02F;
pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         : u16 = 0xC030;
pub const TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256          : u16 = 0xC031;
pub const TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384          : u16 = 0xC032;
pub const TLS_ECDHE_PSK_WITH_RC4_128_SHA                : u16 = 0xC033;
pub const TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA           : u16 = 0xC034;
pub const TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA            : u16 = 0xC035;
pub const TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA            : u16 = 0xC036;
pub const TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256         : u16 = 0xC037;
pub const TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384         : u16 = 0xC038;
pub const TLS_ECDHE_PSK_WITH_NULL_SHA                   : u16 = 0xC039;
pub const TLS_ECDHE_PSK_WITH_NULL_SHA256                : u16 = 0xC03A;
pub const TLS_ECDHE_PSK_WITH_NULL_SHA384                : u16 = 0xC03B;
pub const TLS_RSA_WITH_ARIA_128_CBC_SHA256              : u16 = 0xC03C;
pub const TLS_RSA_WITH_ARIA_256_CBC_SHA384              : u16 = 0xC03D;
pub const TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256           : u16 = 0xC03E;
pub const TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384           : u16 = 0xC03F;
pub const TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256           : u16 = 0xC040;
pub const TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384           : u16 = 0xC041;
pub const TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256          : u16 = 0xC042;
pub const TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384          : u16 = 0xC043;
pub const TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256          : u16 = 0xC044;
pub const TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384          : u16 = 0xC045;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_ARIA_128_CBC_SHA256          : u16 = 0xC046;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_ARIA_256_CBC_SHA384          : u16 = 0xC047;
pub const TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256      : u16 = 0xC048;
pub const TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384      : u16 = 0xC049;
pub const TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256       : u16 = 0xC04A;
pub const TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384       : u16 = 0xC04B;
pub const TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256        : u16 = 0xC04C;
pub const TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384        : u16 = 0xC04D;
pub const TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256         : u16 = 0xC04E;
pub const TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384         : u16 = 0xC04F;
pub const TLS_RSA_WITH_ARIA_128_GCM_SHA256              : u16 = 0xC050;
pub const TLS_RSA_WITH_ARIA_256_GCM_SHA384              : u16 = 0xC051;
pub const TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256          : u16 = 0xC052;
pub const TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384          : u16 = 0xC053;
pub const TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256           : u16 = 0xC054;
pub const TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384           : u16 = 0xC055;
pub const TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256          : u16 = 0xC056;
pub const TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384          : u16 = 0xC057;
pub const TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256           : u16 = 0xC058;
pub const TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384           : u16 = 0xC059;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_ARIA_128_GCM_SHA256          : u16 = 0xC05A;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_ARIA_256_GCM_SHA384          : u16 = 0xC05B;
pub const TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256      : u16 = 0xC05C;
pub const TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384      : u16 = 0xC05D;
pub const TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256       : u16 = 0xC05E;
pub const TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384       : u16 = 0xC05F;
pub const TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256        : u16 = 0xC060;
pub const TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384        : u16 = 0xC061;
pub const TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256         : u16 = 0xC062;
pub const TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384         : u16 = 0xC063;
pub const TLS_PSK_WITH_ARIA_128_CBC_SHA256              : u16 = 0xC064;
pub const TLS_PSK_WITH_ARIA_256_CBC_SHA384              : u16 = 0xC065;
pub const TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256          : u16 = 0xC066;
pub const TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384          : u16 = 0xC067;
pub const TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256          : u16 = 0xC068;
pub const TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384          : u16 = 0xC069;
pub const TLS_PSK_WITH_ARIA_128_GCM_SHA256              : u16 = 0xC06A;
pub const TLS_PSK_WITH_ARIA_256_GCM_SHA384              : u16 = 0xC06B;
pub const TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256          : u16 = 0xC06C;
pub const TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384          : u16 = 0xC06D;
pub const TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256          : u16 = 0xC06E;
pub const TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384          : u16 = 0xC06F;
pub const TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256        : u16 = 0xC070;
pub const TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384        : u16 = 0xC071;
pub const TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256  : u16 = 0xC072;
pub const TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384  : u16 = 0xC073;
pub const TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256   : u16 = 0xC074;
pub const TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384   : u16 = 0xC075;
pub const TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256    : u16 = 0xC076;
pub const TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384    : u16 = 0xC077;
pub const TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256     : u16 = 0xC078;
pub const TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384     : u16 = 0xC079;
pub const TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256          : u16 = 0xC07A;
pub const TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384          : u16 = 0xC07B;
pub const TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256      : u16 = 0xC07C;
pub const TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384      : u16 = 0xC07D;
pub const TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256       : u16 = 0xC07E;
pub const TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384       : u16 = 0xC07F;
pub const TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256      : u16 = 0xC080;
pub const TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384      : u16 = 0xC081;
pub const TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256       : u16 = 0xC082;
pub const TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384       : u16 = 0xC083;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256      : u16 = 0xC084;
#[allow(non_upper_case_globals)]
pub const TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384      : u16 = 0xC085;
pub const TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256  : u16 = 0xC086;
pub const TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384  : u16 = 0xC087;
pub const TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256   : u16 = 0xC088;
pub const TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384   : u16 = 0xC089;
pub const TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256    : u16 = 0xC08A;
pub const TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384    : u16 = 0xC08B;
pub const TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256     : u16 = 0xC08C;
pub const TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384     : u16 = 0xC08D;
pub const TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256          : u16 = 0xC08E;
pub const TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384          : u16 = 0xC08F;
pub const TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256      : u16 = 0xC090;
pub const TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384      : u16 = 0xC091;
pub const TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256      : u16 = 0xC092;
pub const TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384      : u16 = 0xC093;
pub const TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256          : u16 = 0xC094;
pub const TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384          : u16 = 0xC095;
pub const TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256      : u16 = 0xC096;
pub const TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384      : u16 = 0xC097;
pub const TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256      : u16 = 0xC098;
pub const TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384      : u16 = 0xC099;
pub const TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256    : u16 = 0xC09A;
pub const TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384    : u16 = 0xC09B;
pub const TLS_RSA_WITH_AES_128_CCM                      : u16 = 0xC09C;
pub const TLS_RSA_WITH_AES_256_CCM                      : u16 = 0xC09D;
pub const TLS_DHE_RSA_WITH_AES_128_CCM                  : u16 = 0xC09E;
pub const TLS_DHE_RSA_WITH_AES_256_CCM                  : u16 = 0xC09F;
pub const TLS_RSA_WITH_AES_128_CCM_8                    : u16 = 0xC0A0;
pub const TLS_RSA_WITH_AES_256_CCM_8                    : u16 = 0xC0A1;
pub const TLS_DHE_RSA_WITH_AES_128_CCM_8                : u16 = 0xC0A2;
pub const TLS_DHE_RSA_WITH_AES_256_CCM_8                : u16 = 0xC0A3;
pub const TLS_PSK_WITH_AES_128_CCM                      : u16 = 0xC0A4;
pub const TLS_PSK_WITH_AES_256_CCM                      : u16 = 0xC0A5;
pub const TLS_DHE_PSK_WITH_AES_128_CCM                  : u16 = 0xC0A6;
pub const TLS_DHE_PSK_WITH_AES_256_CCM                  : u16 = 0xC0A7;
pub const TLS_PSK_WITH_AES_128_CCM_8                    : u16 = 0xC0A8;
pub const TLS_PSK_WITH_AES_256_CCM_8                    : u16 = 0xC0A9;
pub const TLS_PSK_DHE_WITH_AES_128_CCM_8                : u16 = 0xC0AA;
pub const TLS_PSK_DHE_WITH_AES_256_CCM_8                : u16 = 0xC0AB;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_CCM              : u16 = 0xC0AC;
pub const TLS_ECDHE_ECDSA_WITH_AES_256_CCM              : u16 = 0xC0AD;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8            : u16 = 0xC0AE;
pub const TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8            : u16 = 0xC0AF;
pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   : u16 = 0xCCA8;
pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 : u16 = 0xCCA9;
pub const TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256     : u16 = 0xCCAA;
pub const TLS_PSK_WITH_CHACHA20_POLY1305_SHA256         : u16 = 0xCCAB;
pub const TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256   : u16 = 0xCCAC;
pub const TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256     : u16 = 0xCCAD;
pub const TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256     : u16 = 0xCCAE;

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
