// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use misc::asn1::{Tag,TagType,SetOf,ObjectIdentifier,PrintableString};
use misc::asn1::ber::{BerMode,BerReader,BerResult,BerError,FromBer};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SignedCertificate {
    certificate: Certificate,
    signature: Signature,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Certificate {
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Signature {
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
    CountryName,
}

impl SignedCertificate {
    pub fn from_buf(src: &[u8])
            -> BerResult<SignedCertificate> {
        return BerReader::from_buf(src, BerMode::Der, |parser| {
            return Self::from_ber(parser);
        });
    }
}

impl FromBer for SignedCertificate {
    fn from_ber(parser: &mut BerReader) -> BerResult<Self> {
        return parser.parse_sequence(|parser| {
            let certificate = try!(Certificate::from_ber(parser));
            println!("certificate = {:?}", certificate);
            return Ok(SignedCertificate {
                certificate: Certificate {},
                signature: Signature {},
            });
        });
    }
}

impl FromBer for Certificate {
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
            let issuer = try!(Name::from_ber(parser));
            println!("issuer = {:?}", issuer);
            return Ok(Certificate {
            });
        });
    }
}

const AID_RSA_ENCRYPTION : [u64; 7] = [1, 2, 840, 113549, 1, 1, 1];
const AID_RSAES_OAEP : [u64; 7] = [1, 2, 840, 113549, 1, 1, 7];
const AID_PSPECIFIED : [u64; 7] = [1, 2, 840, 113549, 1, 1, 9];
const AID_RSASSA_PSS : [u64; 7] = [1, 2, 840, 113549, 1, 1, 10];
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
        let rdnseq = try!(
                parser.parse::<Vec<SetOf<NameAttribute>>>());
        return Ok(Name::RdnSequence(rdnseq));
    }
}

const ATTR_COUNTRY_NAME : [u64; 4] = [2, 5, 4, 6];

impl FromBer for NameAttribute {
    fn from_ber(parser: &mut BerReader) -> BerResult<Self> {
        parser.parse_sequence(|parser| {
            let oid = try!(parser.parse::<ObjectIdentifier>());
            println!("oid = {:?}", oid);
            if *oid == ATTR_COUNTRY_NAME {
                let hoge = try!(parser.parse::<PrintableString>());
                return Ok(NameAttribute::CountryName);
            } else {
                return Err(BerError::Invalid);
            }
        })
    }
}
