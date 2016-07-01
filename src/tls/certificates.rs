// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use std::io::Write;

use num::bigint::BigUint;

use misc::asn1::{Tag,TagType,SetOf,ObjectIdentifier,PrintableString,UtcTime,BitString};
use misc::asn1::ber::{BerMode,BerReader,BerResult,BerError,FromBer};

use sha2::SHA256Writer;

pub type Certificate = Signed<TBSCertificate>;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Signed<T> {
    to_be_signed: T,
    to_be_signed_raw: Vec<u8>,
    signature: Signature,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct TBSCertificate {
    version: i64,
    certificate_serial_number: i64,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfo,
    issuer_unique_identifier: Option<()>,
    subject_unique_identifier: Option<()>,
    extensions: Option<Vec<Extension>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Signature {
    algorithm_identifier: AlgorithmIdentifier,
    encrypted: BitString,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum AlgorithmIdentifier {
    RsaEncryption,
    // RsaesOaep { ... },
    // Pspecified(Vec<u8>),
    // RsassaPss { ... },
    Md2WithRsaEncryption,
    Md5WithRsaEncryption,
    Sha1WithRsaEncryption,
    Sha256WithRsaEncryption,
    Sha384WithRsaEncryption,
    Sha512WithRsaEncryption,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Name {
    RdnSequence(Vec<SetOf<NameAttribute>>),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum NameAttribute {
    CommonName(PrintableString),
    CountryName(PrintableString),
    OrganizationName(PrintableString),
    OrganizationalUnitName(PrintableString),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Validity {
    not_before: Time,
    not_after: Time,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Time {
    UtcTime(UtcTime),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SubjectPublicKeyInfo {
    algorithm: AlgorithmIdentifier,
    subject_public_key: BitString,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Extension {
    oid: ObjectIdentifier,
    critical: bool,
    extn_value: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct RsaPublicKey {
    modulus: BigUint,
    public_exponent: BigUint,
}

fn powmod_naive(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint {
    let mut x = BigUint::from(1u32);
    for bb in b.to_bytes_be() {
        for i in (0..8).rev() {
            x = (x.clone() * x.clone()) % m.clone();
            if (bb & (1 << i)) != 0 {
                x = (x.clone() * a.clone()) % m.clone();
            }
        }
    }
    return x;
}

impl<T> Signed<T> {
    pub fn to_be_signed(&self) -> &T {
        return &self.to_be_signed;
    }
    pub fn verify(&self, cert: &TBSCertificate) -> bool {
        match self.signature.algorithm_identifier {
            AlgorithmIdentifier::RsaEncryption => {
                // TODO
                return false;
            },
            // AlgorithmIdentifier::RsaesOaep { ... } => {},
            // AlgorithmIdentifier::Pspecified(Vec<u8>) => {},
            // AlgorithmIdentifier::RsassaPss { ... } => {},
            AlgorithmIdentifier::Md2WithRsaEncryption => {
                // TODO
                return false;
            },
            AlgorithmIdentifier::Md5WithRsaEncryption => {
                // TODO
                return false;
            },
            AlgorithmIdentifier::Sha1WithRsaEncryption => {
                // TODO
                return false;
            },
            AlgorithmIdentifier::Sha256WithRsaEncryption => {
                if self.signature.encrypted.unused_bits != 0 {
                    return false;
                }
                let signature = &self.signature.encrypted.buf;
                println!("signature = {:?}", signature);
                let mut digest_info = Vec::new();
                digest_info.extend_from_slice(
                    &[0x30, 0x31, 0x30, 0x0D, 0x06, 0x09,
                    0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                    0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]);
                {
                    let mut hasher = SHA256Writer::new();
                    hasher.write_all(&self.to_be_signed_raw).unwrap();
                    digest_info.extend_from_slice(&hasher.sum());
                }
                println!("digest_info = {:?}", digest_info);
                if signature.len() < digest_info.len() + 11 {
                    return false;
                }
                let mut encoded_message = Vec::new();
                encoded_message.push(0x00);
                encoded_message.push(0x01);
                for _ in 0 .. signature.len()-digest_info.len()-3 {
                    encoded_message.push(0xFF);
                }
                encoded_message.push(0x00);
                encoded_message.extend_from_slice(&digest_info);
                println!("encoded_message = {:?}", encoded_message);
                if cert.subject_public_key_info.algorithm !=
                        AlgorithmIdentifier::RsaEncryption {
                    return false;
                }
                if cert.subject_public_key_info
                        .subject_public_key.unused_bits != 0 {
                    return false;
                }
                let key_raw = &cert.subject_public_key_info
                    .subject_public_key.buf;
                println!("key_raw = {:?}", key_raw);
                let key;
                match RsaPublicKey::from_buf(&key_raw, BerMode::Der) {
                    Ok(key_) => { key = key_; }
                    Err(_) => { return false; }
                }
                println!("key = {:?}", key);
                let signature_num = BigUint::from_bytes_be(signature);
                println!("signature_num = {}", signature_num);
                let converted_signature_num = powmod_naive(
                    &signature_num, &key.public_exponent, &key.modulus);
                println!("converted_signature_num = {}",
                         converted_signature_num);
                let encoded_message_num =
                    BigUint::from_bytes_be(&encoded_message);
                println!("encoded_message_num = {}", encoded_message_num);
                return converted_signature_num == encoded_message_num;
            },
            AlgorithmIdentifier::Sha384WithRsaEncryption => {
                // TODO
                return false;
            },
            AlgorithmIdentifier::Sha512WithRsaEncryption => {
                // TODO
                return false;
            },
        };
    }
}

impl<T:FromBer> FromBer for Signed<T> {
    fn from_ber(parser: &mut BerReader) -> BerResult<Self> {
        return parser.parse_sequence(|parser| {
            let (to_be_signed, to_be_signed_raw) =
                try!(parser.parse_with_buffer(|parser| {
                    T::from_ber(parser)
                }));
            let algorithm_identifier = try!(
                parser.parse::<AlgorithmIdentifier>());
            let encrypted = try!(
                parser.parse::<BitString>());
            return Ok(Signed {
                to_be_signed: to_be_signed,
                to_be_signed_raw: to_be_signed_raw.to_vec(),
                signature: Signature {
                    algorithm_identifier: algorithm_identifier,
                    encrypted: encrypted,
                },
            });
        });
    }
}

impl FromBer for TBSCertificate {
    fn from_ber(parser: &mut BerReader) -> BerResult<Self> {
        return parser.parse_sequence(|parser| {
            let version = try!(parser.parse_default(0, |parser| {
                parser.parse_tagged(Tag::context(0), TagType::Explicit,
                        |parser| {
                    parser.parse::<i64>()
                })
            }));
            let certificate_serial_number = try!(parser.parse::<i64>());
            let signature_algorithm = try!(AlgorithmIdentifier::from_ber(parser));
            let issuer = try!(parser.parse::<Name>());
            let validity = try!(parser.parse::<Validity>());
            let subject = try!(parser.parse::<Name>());
            let subject_public_key_info =
                try!(parser.parse::<SubjectPublicKeyInfo>());
            // TODO: issuer_unique_identifier
            // TODO: subject_unique_identifier
            let extensions = try!(parser.parse_optional(|parser| {
                parser.parse_tagged(Tag::context(3), TagType::Explicit,
                    |parser| {
                    parser.parse::<Vec<Extension>>()
                })
            }));
            return Ok(TBSCertificate {
                version: version,
                certificate_serial_number: certificate_serial_number,
                issuer: issuer,
                validity: validity,
                subject: subject,
                subject_public_key_info: subject_public_key_info,
                issuer_unique_identifier: None,
                subject_unique_identifier: None,
                extensions: extensions,
            });
        });
    }
}

const AID_RSA_ENCRYPTION : [u64; 7] = [1, 2, 840, 113549, 1, 1, 1];
// const AID_RSAES_OAEP : [u64; 7] = [1, 2, 840, 113549, 1, 1, 7];
// const AID_PSPECIFIED : [u64; 7] = [1, 2, 840, 113549, 1, 1, 9];
// const AID_RSASSA_PSS : [u64; 7] = [1, 2, 840, 113549, 1, 1, 10];
const AID_MD2_WITH_RSA_ENCRYPTION : [u64; 7] =
    [1, 2, 840, 113549, 1, 1, 2];
const AID_MD5_WITH_RSA_ENCRYPTION : [u64; 7] =
    [1, 2, 840, 113549, 1, 1, 4];
const AID_SHA1_WITH_RSA_ENCRYPTION : [u64; 7] =
    [1, 2, 840, 113549, 1, 1, 5];
const AID_SHA256_WITH_RSA_ENCRYPTION : [u64; 7] =
    [1, 2, 840, 113549, 1, 1, 11];
const AID_SHA384_WITH_RSA_ENCRYPTION : [u64; 7] =
    [1, 2, 840, 113549, 1, 1, 12];
const AID_SHA512_WITH_RSA_ENCRYPTION : [u64; 7] =
    [1, 2, 840, 113549, 1, 1, 13];

impl FromBer for AlgorithmIdentifier {
    fn from_ber(parser: &mut BerReader) -> BerResult<Self> {
        return parser.parse_sequence(|parser| {
            let oid = try!(parser.parse::<ObjectIdentifier>());
            if *oid == AID_RSA_ENCRYPTION {
                try!(parser.parse::<()>());
                return Ok(AlgorithmIdentifier::RsaEncryption);
            } else if *oid == AID_MD2_WITH_RSA_ENCRYPTION {
                try!(parser.parse::<()>());
                return Ok(AlgorithmIdentifier::Md2WithRsaEncryption);
            } else if *oid == AID_MD5_WITH_RSA_ENCRYPTION {
                try!(parser.parse::<()>());
                return Ok(AlgorithmIdentifier::Md5WithRsaEncryption);
            } else if *oid == AID_SHA1_WITH_RSA_ENCRYPTION {
                try!(parser.parse::<()>());
                return Ok(AlgorithmIdentifier::Sha1WithRsaEncryption);
            } else if *oid == AID_SHA256_WITH_RSA_ENCRYPTION {
                try!(parser.parse::<()>());
                return Ok(AlgorithmIdentifier::Sha256WithRsaEncryption);
            } else if *oid == AID_SHA384_WITH_RSA_ENCRYPTION {
                try!(parser.parse::<()>());
                return Ok(AlgorithmIdentifier::Sha384WithRsaEncryption);
            } else if *oid == AID_SHA512_WITH_RSA_ENCRYPTION {
                try!(parser.parse::<()>());
                return Ok(AlgorithmIdentifier::Sha512WithRsaEncryption);
            } else {
                return Err(BerError::Invalid);
            }
        });
    }
}

impl FromBer for Name {
    fn from_ber(parser: &mut BerReader) -> BerResult<Self> {
        // TODO: other types
        let rdnseq = try!(
                parser.parse::<Vec<SetOf<NameAttribute>>>());
        return Ok(Name::RdnSequence(rdnseq));
    }
}

const ATTR_COMMON_NAME : [u64; 4] = [2, 5, 4, 3];
const ATTR_COUNTRY_NAME : [u64; 4] = [2, 5, 4, 6];
const ATTR_ORGANIZATION_NAME : [u64; 4] = [2, 5, 4, 10];
const ATTR_ORGANIZATIONAL_UNIT_NAME : [u64; 4] = [2, 5, 4, 11];

impl FromBer for NameAttribute {
    fn from_ber(parser: &mut BerReader) -> BerResult<Self> {
        parser.parse_sequence(|parser| {
            let oid = try!(parser.parse::<ObjectIdentifier>());
            if *oid == ATTR_COMMON_NAME {
                // TODO: other type of names...
                let name = try!(parser.parse::<PrintableString>());
                return Ok(NameAttribute::CommonName(name));
            } else if *oid == ATTR_COUNTRY_NAME {
                let name = try!(parser.parse::<PrintableString>());
                if name.len() != 2 {
                    return Err(BerError::Invalid);
                }
                return Ok(NameAttribute::CountryName(name));
            } else if *oid == ATTR_ORGANIZATION_NAME {
                // TODO: other type of names...
                let name = try!(parser.parse::<PrintableString>());
                return Ok(NameAttribute::OrganizationName(name));
            } else if *oid == ATTR_ORGANIZATIONAL_UNIT_NAME {
                // TODO: other type of names...
                let name = try!(parser.parse::<PrintableString>());
                return Ok(NameAttribute::OrganizationalUnitName(name));
            } else {
                println!("oid = {:?}", oid);
                println!("remaining = {:?}", parser.remaining_buffer());
                return Err(BerError::Invalid);
            }
        })
    }
}

impl FromBer for Validity {
    fn from_ber(parser: &mut BerReader) -> BerResult<Self> {
        parser.parse_sequence(|parser| {
            let not_before = try!(parser.parse::<Time>());
            let not_after = try!(parser.parse::<Time>());
            return Ok(Validity {
                not_before: not_before,
                not_after: not_after,
            });
        })
    }
}

impl FromBer for Time {
    fn from_ber(parser: &mut BerReader) -> BerResult<Self> {
        // TODO: GeneralizedTime
        let time = try!(parser.parse::<UtcTime>());
        return Ok(Time::UtcTime(time));
    }
}

impl FromBer for SubjectPublicKeyInfo {
    fn from_ber(parser: &mut BerReader) -> BerResult<Self> {
        parser.parse_sequence(|parser| {
            let algorithm = try!(parser.parse::<AlgorithmIdentifier>());
            let subject_public_key = try!(parser.parse::<BitString>());
            return Ok(SubjectPublicKeyInfo {
                algorithm: algorithm,
                subject_public_key: subject_public_key,
            });
        })
    }
}

impl FromBer for Extension {
    fn from_ber(parser: &mut BerReader) -> BerResult<Self> {
        parser.parse_sequence(|parser| {
            let oid = try!(parser.parse::<ObjectIdentifier>());
            let critical = try!(parser.parse_default(false, |parser| {
                parser.parse::<bool>()
            }));
            let extn_value = try!(parser.parse::<Vec<u8>>());
            return Ok(Extension {
                oid: oid,
                critical: critical,
                extn_value: extn_value,
            });
        })
    }
}

impl FromBer for RsaPublicKey {
    fn from_ber(parser: &mut BerReader) -> BerResult<Self> {
        parser.parse_sequence(|parser| {
            let modulus = try!(parser.parse::<BigUint>());
            let public_exponent = try!(parser.parse::<BigUint>());
            return Ok(RsaPublicKey {
                modulus: modulus,
                public_exponent: public_exponent,
            });
        })
    }
}
