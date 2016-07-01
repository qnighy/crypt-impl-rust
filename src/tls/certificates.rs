// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use misc::asn1::{Tag,TagType,SetOf,ObjectIdentifier,PrintableString,UtcTime,BitString};
use misc::asn1::ber::{BerMode,BerReader,BerResult,BerError,FromBer};

pub type Certificate = Signed<TBSCertificate>;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Signed<T> {
    to_be_signed: T,
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

impl<T:FromBer> Signed<T> {
    pub fn from_buf(src: &[u8])
            -> BerResult<Signed<T>> {
        return BerReader::from_buf(src, BerMode::Der, |parser| {
            return Self::from_ber(parser);
        });
    }
}

impl<T:FromBer> FromBer for Signed<T> {
    fn from_ber(parser: &mut BerReader) -> BerResult<Self> {
        return parser.parse_sequence(|parser| {
            let to_be_signed = try!(T::from_ber(parser));
            let algorithm_identifier = try!(
                parser.parse::<AlgorithmIdentifier>());
            println!("algorithm_identifier = {:?}", algorithm_identifier);
            let encrypted = try!(
                parser.parse::<BitString>());
            println!("encrypted = {:?}", encrypted);
            return Ok(Signed {
                to_be_signed: to_be_signed,
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
            println!("version = {:?}", version);
            let certificate_serial_number = try!(parser.parse::<i64>());
            println!("certificate_serial_number = {:?}", certificate_serial_number);
            let signature_algorithm = try!(AlgorithmIdentifier::from_ber(parser));
            println!("signature_algorithm = {:?}", signature_algorithm);
            let issuer = try!(parser.parse::<Name>());
            println!("issuer = {:?}", issuer);
            let validity = try!(parser.parse::<Validity>());
            println!("validity = {:?}", validity);
            let subject = try!(parser.parse::<Name>());
            println!("subject = {:?}", subject);
            let subject_public_key_info =
                try!(parser.parse::<SubjectPublicKeyInfo>());
            println!("subject_public_key_info = {:?}", subject_public_key_info);
            // TODO: issuer_unique_identifier
            // TODO: subject_unique_identifier
            let extensions = try!(parser.parse_optional(|parser| {
                parser.parse_tagged(Tag::context(3), TagType::Explicit,
                    |parser| {
                    parser.parse::<Vec<Extension>>()
                })
            }));
            println!("extensions = {:?}", extensions);
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
