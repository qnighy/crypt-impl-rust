// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

#![allow(dead_code)] // TODO
#![allow(unused_mut)] // TODO

extern crate byteorder;
extern crate time;
extern crate rand;

use std::cmp;
use std::io::{self,Read,Write,Seek,Cursor};
use self::byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt, NetworkEndian};

pub struct TLSStream<S : Read + Write> {
    inner: S,
    record_read_buf: Vec<u8>,
    record_write_buf: Vec<u8>,
    read_bufs: [Cursor<Vec<u8>>; 4],
    write_bufs: [Cursor<Vec<u8>>; 4],
}

impl<S: Read + Write> TLSStream<S> {
    pub fn new(inner: S) -> TLSStream<S> {
        let mut ret = TLSStream::<S> {
            inner: inner,
            record_read_buf: Vec::with_capacity(2048),
            record_write_buf: Vec::with_capacity(2048),
            read_bufs: [
                Cursor::new(Vec::with_capacity(1024)),
                Cursor::new(Vec::with_capacity(1024)),
                Cursor::new(Vec::with_capacity(1024)),
                Cursor::new(Vec::with_capacity(1024)),
            ],
            write_bufs: [
                Cursor::new(Vec::with_capacity(1024)),
                Cursor::new(Vec::with_capacity(1024)),
                Cursor::new(Vec::with_capacity(1024)),
                Cursor::new(Vec::with_capacity(1024)),
            ],
        };
        return ret;
    }
    fn send_alert(&mut self, alert: Alert) -> io::Result<()> {
        try!(alert.write_to(&mut self.write_bufs[ALERT_IDX]));
        try!(self.flush(ALERT_IDX));
        try!(self.flush_record());
        return Ok(());
    }
    fn send_client_hello(&mut self) -> io::Result<()> {
        let mut client_hello = HandshakeMessage::ClientHello {
            random: TLSRandom::new(),
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
                CompressionMethod { id: 0, },
            ],
            extensions: vec![
                HelloExtension::ServerName(vec![
                    ServerName::HostName(b"qnighy.info".to_vec()),
                ]),
            ],
        };
        try!(client_hello.write_to(&mut self.write_bufs[HANDSHAKE_IDX]));
        try!(self.flush(HANDSHAKE_IDX));
        try!(self.flush_record());
        return Ok(());
    }
    fn recv_server_hello(&mut self) -> io::Result<()> {
        try!(self.record_read());
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
                CONTENT_TYPES[content_idx],
                0x03, 0x03, (len >> 8) as u8, len as u8,
            ]);
            self.record_write_buf.extend(vec[pos .. pos + len].iter());
            pos += len;
        }
        vec.clear();
        return Ok(());
    }
    fn record_read(&mut self) -> io::Result<()> {
        self.record_read_buf.reserve(1024);
        let len = self.record_read_buf.len();
        let cap = self.record_read_buf.capacity();
        self.record_read_buf.resize(cap, 0);
        let num_read = try!(
            self.inner.read(&mut self.record_read_buf[len ..]));
        self.record_read_buf.resize(len + num_read, 0);
        return Ok(());
    }
    fn record_consume(&mut self) -> io::Result<()> {
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
                try!(self.record_read());
            } else {
                let buf = &mut self.record_read_buf;
                let content_type = buf[0];
                let version_major = buf[1];
                let version_minor = buf[2];
                // TODO
                assert_eq!(version_major, 3);
                assert_eq!(version_minor, 3);
                let content_idx = match content_type {
                    20 => CHANGE_CIPHER_SPEC_IDX,
                    21 => ALERT_IDX,
                    22 => HANDSHAKE_IDX,
                    23 => APPLICATION_DATA_IDX,
                    _ => {
                        // TODO
                        panic!("Unknown content type");
                    }
                };
                {
                    let ciphertext = &buf[5 .. 5+len];
                    // TODO: it's just the ciphertext itself now!
                    let plaintext = ciphertext;
                    self.read_bufs[content_idx].get_mut()
                        .extend(plaintext.iter());
                }
                buf.drain(0 .. 5+len);
                // println!("{:?}", &self.read_bufs[content_idx]);
                return Ok(());
            }
        }
    }
    fn check_change_cipher_spec(&mut self) -> io::Result<()> {
        // TODO
        return Ok(());
    }
    fn check_alert(&mut self) -> io::Result<()> {
        // TODO
        return Ok(());
    }
    fn check_handshake(&mut self) -> io::Result<()> {
        let cursor = &mut self.read_bufs[HANDSHAKE_IDX];
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
        let message = try!(HandshakeMessage::read_from(cursor));
        println!("{:?}", &message);
        let position = cursor.position() as usize;
        cursor.set_position(0);
        cursor.get_mut().drain(0 .. position);
        return Ok(());
    }
    fn read_buf(&mut self) -> io::Result<()> {
        self.record_read_buf.reserve(1024);
        let len = self.record_read_buf.len();
        let cap = self.record_read_buf.capacity();
        self.record_read_buf.resize(cap, 0);
        let num_read = try!(
            self.inner.read(&mut self.record_read_buf[len ..]));
        self.record_read_buf.resize(len + num_read, 0);
        return Ok(());
    }
}

const MAX_CHUNK_LEN : usize = 16384;
const CONTENT_TYPES : [u8; 4] = [20, 21, 22, 23];
const CHANGE_CIPHER_SPEC_IDX : usize = 0;
const ALERT_IDX : usize = 1;
const HANDSHAKE_IDX : usize = 2;
const APPLICATION_DATA_IDX : usize = 3;
const CLIENT_HELLO : u8 = 0x01;
const SERVER_HELLO : u8 = 0x02;

const EXTENSION_SERVER_NAME : u16 = 0;
const EXTENSION_MAX_FRAGMENT_LENGTH : u16 = 1;
const EXTENSION_CLIENT_CERTIFICATE_URL : u16 = 2;
const EXTENSION_TRUSTED_CA_KEYS : u16 = 3;
const EXTENSION_TRUNCATED_HMAC : u16 = 4;
const EXTENSION_STATUS_REQUEST : u16 = 5;
const EXTENSION_SIGNATURE_ALGORITHMS : u16 = 13;

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
enum ContentType {
    ChangeCipherSpec, Alert, Handshake, ApplicationData, Heartbeat,
}

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
struct ProtocolVersion {
    major: u8,
    minor: u8,
}

struct TLSCiphertext {
    content_type: ContentType,
    version: ProtocolVersion,
    fragment: Vec<u8>,
}

struct TLSPlaintext {
    content_type: ContentType,
    version: ProtocolVersion,
    fragment: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
enum AlertLevel {
    Warning, Fatal,
}

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
enum AlertDescription {
    CloseNotify, UnexpectedMessage, BadRecordMac, DecryptionFailed,
    RecordOverflow, DecompressionFailure, HandshakeFailure,
    NoCertificateRESERVED, BadCertificate, UnsupportedCertificate,
    CertificateRevoked, CertificateExpired, CertificateUnknown,
    IllegalParameter, UnknownCA, AccessDenied, DecodeError, DecryptError,
    ExportRestrictionRESERVED, ProtocolVersion, InsufficientSecurity,
    InternalError, InappropriateFallback, UserCanceled, NoRenegotiation,
    UnsupportedExtension, CertificateUnobtainable, UnrecognizedName,
    BadCertificateStatusResponse, BadCertificateHashValue,
    UnknownPSKIdentity,
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
    // Certificate,
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

#[derive(Debug)]
struct TLSRandom {
    time: u32,
    random_bytes: [u8; 28],
}

#[derive(Debug)]
struct SessionID {
    length: usize,
    bytes: [u8; 32],
}

#[derive(Debug)]
struct CipherSuite {
    id: u16,
}

#[derive(Debug)]
struct CompressionMethod {
    id: u8,
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

struct LengthMarkR16 {
    end: u64,
}

struct LengthMarkR24 {
    end: u64,
}

struct LengthMarkW16 {
    begin: u64,
}

struct LengthMarkW24 {
    begin: u64,
}

impl LengthMarkR16 {
    fn new<R:Read+Seek>(src: &mut R) -> io::Result<Self> {
        let length = try!(src.read_u16::<NetworkEndian>());
        let begin = try!(src.seek(io::SeekFrom::Current(0)));
        return Ok(LengthMarkR16 {
            end: begin + (length as u64),
        });
    }
    fn is_remaining<R:Read+Seek>(&self, src: &mut R) -> io::Result<bool> {
        let current = try!(src.seek(io::SeekFrom::Current(0)));
        return Ok(current < self.end);
    }
    fn check<R:Read+Seek>(self, src: &mut R) -> io::Result<()> {
        let current = try!(src.seek(io::SeekFrom::Current(0)));
        if current != self.end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData, "Invalid Length"));
        }
        return Ok(());
    }
}

impl LengthMarkR24 {
    fn new<R:Read+Seek>(src: &mut R) -> io::Result<Self> {
        let length = {
            let length0 = try!(src.read_u8()) as u32;
            let length1 = try!(src.read_u8()) as u32;
            let length2 = try!(src.read_u8()) as u32;
            (length0 << 16) | (length1 << 8) | length2
        };
        let begin = try!(src.seek(io::SeekFrom::Current(0)));
        return Ok(LengthMarkR24 {
            end: begin + (length as u64),
        });
    }
    fn is_remaining<R:Read+Seek>(&self, src: &mut R) -> io::Result<bool> {
        let current = try!(src.seek(io::SeekFrom::Current(0)));
        return Ok(current < self.end);
    }
    fn check<R:Read+Seek>(self, src: &mut R) -> io::Result<()> {
        let current = try!(src.seek(io::SeekFrom::Current(0)));
        if current != self.end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData, "Invalid Length"));
        }
        return Ok(());
    }
}

impl LengthMarkW16 {
    fn new<W:Write+Seek>(dest: &mut W) -> io::Result<Self> {
        let begin = try!(dest.seek(io::SeekFrom::Current(0)));
        try!(dest.write_u16::<NetworkEndian>(0));
        return Ok(LengthMarkW16 {
            begin: begin,
        });
    }
    fn record<W:Write+Seek>(self, dest: &mut W) -> io::Result<()> {
        let current = try!(dest.seek(io::SeekFrom::Current(0)));
        let length = current - self.begin - 2;
        assert!(length < 65536);
        try!(dest.seek(io::SeekFrom::Start(self.begin)));
        try!(dest.write_u16::<NetworkEndian>(length as u16));
        try!(dest.seek(io::SeekFrom::Start(current)));
        return Ok(());
    }
}

impl LengthMarkW24 {
    fn new<W:Write+Seek>(dest: &mut W) -> io::Result<Self> {
        let begin = try!(dest.seek(io::SeekFrom::Current(0)));
        try!(dest.write_u8(0));
        try!(dest.write_u8(0));
        try!(dest.write_u8(0));
        return Ok(LengthMarkW24 {
            begin: begin,
        });
    }
    fn record<W:Write+Seek>(self, dest: &mut W) -> io::Result<()> {
        let current = try!(dest.seek(io::SeekFrom::Current(0)));
        let length = current - self.begin - 3;
        assert!(length < 16777216);
        try!(dest.seek(io::SeekFrom::Start(self.begin)));
        try!(dest.write_u8((length >> 16) as u8));
        try!(dest.write_u8((length >> 8) as u8));
        try!(dest.write_u8((length >> 0) as u8));
        try!(dest.seek(io::SeekFrom::Start(current)));
        return Ok(());
    }
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
    fn read_from<R:Read>(src: &mut R) -> io::Result<Self> {
        let id = try!(src.read_u8());
        let ret = match id {
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            24 => ContentType::Heartbeat,
            _  => {
                // TODO
                panic!("Unknown ContentType");
            }
        };
        return Ok(ret);
    }
    fn write_to<W:Write>(self, dest: &mut W) -> io::Result<()> {
        let id = match self {
            ContentType::ChangeCipherSpec => 20,
            ContentType::Alert => 21,
            ContentType::Handshake => 22,
            ContentType::Heartbeat => 23,
            _ => {
                // TODO
                panic!("Unknown ContentType");
            }
        };
        try!(dest.write_u8(id));
        return Ok(());
    }
}

impl ProtocolVersion {
    fn read_from<R:Read>(src: &mut R) -> io::Result<Self> {
        let major = try!(src.read_u8());
        let minor = try!(src.read_u8());
        let ret = ProtocolVersion {
            major: major,
            minor: minor,
        };
        return Ok(ret);
    }
    fn write_to<W:Write>(&self, dest: &mut W) -> io::Result<()> {
        try!(dest.write_u8(self.major));
        try!(dest.write_u8(self.minor));
        return Ok(());
    }
}

impl TLSCiphertext {
    fn read_from<R:Read>(src: &mut R) -> io::Result<Self> {
        let content_type = try!(ContentType::read_from(src));
        let version = try!(ProtocolVersion::read_from(src));
        let length = try!(src.read_u16::<NetworkEndian>()) as usize;
        let mut fragment = vec![0; length];
        try!(src.read_exact(&mut fragment));
        let ret = TLSCiphertext {
            content_type: content_type,
            version: version,
            fragment: fragment,
        };
        return Ok(ret);
    }
    fn write_to<W:Write>(&self, dest: &mut W) -> io::Result<()> {
        try!(self.content_type.write_to(dest));
        try!(self.version.write_to(dest));
        try!(dest.write_u16::<NetworkEndian>(self.fragment.len() as u16));
        try!(dest.write_all(&self.fragment));
        return Ok(());
    }
}

impl AlertLevel {
    fn from_id(id: u8) -> AlertLevel {
        return match id {
            1 => AlertLevel::Warning,
            2 => AlertLevel::Fatal,
            _ => panic!("Unknown Alert Level ID"), // TODO
        };
    }
    fn id(self) -> u8 {
        return match self {
            AlertLevel::Warning => 1,
            AlertLevel::Fatal => 2,
        };
    }
}

impl AlertDescription {
    fn from_id(id: u8) -> AlertDescription {
        return match id {
              0 => AlertDescription::CloseNotify,
             10 => AlertDescription::UnexpectedMessage,
             20 => AlertDescription::BadRecordMac,
             21 => AlertDescription::DecryptionFailed,
             22 => AlertDescription::RecordOverflow,
             30 => AlertDescription::DecompressionFailure,
             40 => AlertDescription::HandshakeFailure,
             41 => AlertDescription::NoCertificateRESERVED,
             42 => AlertDescription::BadCertificate,
             43 => AlertDescription::UnsupportedCertificate,
             44 => AlertDescription::CertificateRevoked,
             45 => AlertDescription::CertificateExpired,
             46 => AlertDescription::CertificateUnknown,
             47 => AlertDescription::IllegalParameter,
             48 => AlertDescription::UnknownCA,
             49 => AlertDescription::AccessDenied,
             50 => AlertDescription::DecodeError,
             51 => AlertDescription::DecryptError,
             60 => AlertDescription::ExportRestrictionRESERVED,
             70 => AlertDescription::ProtocolVersion,
             71 => AlertDescription::InsufficientSecurity,
             80 => AlertDescription::InternalError,
             86 => AlertDescription::InappropriateFallback,
             90 => AlertDescription::UserCanceled,
            100 => AlertDescription::NoRenegotiation,
            110 => AlertDescription::UnsupportedExtension,
            111 => AlertDescription::CertificateUnobtainable,
            112 => AlertDescription::UnrecognizedName,
            113 => AlertDescription::BadCertificateStatusResponse,
            114 => AlertDescription::BadCertificateHashValue,
            115 => AlertDescription::UnknownPSKIdentity,
            _   => panic!("Unknown Alert Description ID"), // TODO
        };
    }
    fn id(self) -> u8 {
        return match self {
            AlertDescription::CloseNotify => 0,
            AlertDescription::UnexpectedMessage => 10,
            AlertDescription::BadRecordMac => 20,
            AlertDescription::DecryptionFailed => 21,
            AlertDescription::RecordOverflow => 22,
            AlertDescription::DecompressionFailure => 30,
            AlertDescription::HandshakeFailure => 40,
            AlertDescription::NoCertificateRESERVED => 41,
            AlertDescription::BadCertificate => 42,
            AlertDescription::UnsupportedCertificate => 43,
            AlertDescription::CertificateRevoked => 44,
            AlertDescription::CertificateExpired => 45,
            AlertDescription::CertificateUnknown => 46,
            AlertDescription::IllegalParameter => 47,
            AlertDescription::UnknownCA => 48,
            AlertDescription::AccessDenied => 49,
            AlertDescription::DecodeError => 50,
            AlertDescription::DecryptError => 51,
            AlertDescription::ExportRestrictionRESERVED => 60,
            AlertDescription::ProtocolVersion => 70,
            AlertDescription::InsufficientSecurity => 71,
            AlertDescription::InternalError => 80,
            AlertDescription::InappropriateFallback => 86,
            AlertDescription::UserCanceled => 90,
            AlertDescription::NoRenegotiation => 100,
            AlertDescription::UnsupportedExtension => 110,
            AlertDescription::CertificateUnobtainable => 111,
            AlertDescription::UnrecognizedName => 112,
            AlertDescription::BadCertificateStatusResponse => 113,
            AlertDescription::BadCertificateHashValue => 114,
            AlertDescription::UnknownPSKIdentity => 115,
        };
    }
}

impl Alert {
    fn read_from<R:Read>(src: &mut R) -> io::Result<Self> {
        let level = try!(src.read_u8());
        let description = try!(src.read_u8());
        return Ok(Alert {
            level: AlertLevel::from_id(level),
            description: AlertDescription::from_id(description),
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
                println!("{:?}", &server_version);
                let random = try!(TLSRandom::read_from(src));
                println!("{:?}", &random);
                let session_id = try!(SessionID::read_from(src));
                println!("{:?}", &session_id);
                let cipher_suite = try!(CipherSuite::read_from(src));
                println!("{:?}", &cipher_suite);
                let compression_method =
                    try!(CompressionMethod::read_from(src));
                println!("{:?}", &compression_method);
                let mut extensions = Vec::new();
                if try!(handshake_mark.is_remaining(src)) {
                    let extensions_mark = try!(LengthMarkR16::new(src));
                    while try!(extensions_mark.is_remaining(src)) {
                        extensions.push(try!(HelloExtension::read_from(src)));
                    }
                    try!(extensions_mark.check(src));
                }
                println!("{:?}", &extensions);
                ret = HandshakeMessage::ServerHello {
                    server_version: server_version,
                    random: random,
                    session_id: session_id,
                    cipher_suite: cipher_suite,
                    compression_method: compression_method,
                    extensions: extensions,
                };
                println!("{:?}", &ret);
            },
            _ => {
                // TODO
                panic!("TODO: Unknown Handshake Type");
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
        };
        return Ok(());
    }
}

impl TLSRandom {
    fn new() -> TLSRandom {
        let mut ret = TLSRandom {
            time: time::now().to_timespec().sec as u32,
            random_bytes: [0; 28],
        };
        for i in 0..7 {
            NetworkEndian::write_u32(
                &mut ret.random_bytes[i*4 .. i*4+4],
                rand::random::<u32>());
        }
        return ret;
    }
    fn read_from<R:Read>(src: &mut R) -> io::Result<Self> {
        let time = try!(src.read_u32::<NetworkEndian>());
        let mut ret = TLSRandom {
            time: time,
            random_bytes: [0; 28],
        };
        try!(src.read(&mut ret.random_bytes));
        return Ok(ret);
    }
    fn write_to<W:Write>(&self, dest: &mut W) -> io::Result<()> {
        try!(dest.write_u32::<NetworkEndian>(self.time));
        try!(dest.write_all(&self.random_bytes));
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
    fn read_from<R:Read>(src: &mut R) -> io::Result<Self> {
        let id = try!(src.read_u8());
        let ret = CompressionMethod {
            id: id
        };
        return Ok(ret);
    }
    fn write_to<W:Write>(&self, dest: &mut W) -> io::Result<()> {
        try!(dest.write_u8(self.id));
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

struct SecurityParameters {
    entity: ConnectionEnd,
    enc_key_length: u8,
    block_length: u8,
    fixed_iv_length: u8,
    record_iv_length: u8,
    master_secret: [u8; 48],
    client_random: [u8; 32],
    server_random: [u8; 32],
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

#[cfg(test)]
#[test]
fn foo() {
    use std::net::TcpStream;
    let stream = TcpStream::connect("qnighy.info:443").unwrap();
    let mut stream = TLSStream::new(stream);
    stream.send_client_hello().unwrap();

    stream.record_consume().unwrap();
    stream.check_change_cipher_spec().unwrap();
    stream.check_alert().unwrap();
    stream.check_handshake().unwrap();
    panic!();
}
