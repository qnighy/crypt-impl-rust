// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use std::cmp::Ordering;
use std::error::{Error};
use std::fmt::{self,Display};
use std::hash::Hash;
use std::io;

use misc::asn1::*;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum BerError {
    TagMismatch, Eof, Extra, IntegerOverflow, Invalid,
}

pub type BerResult<T> = Result<T, BerError>;

fn wrap_tag_mismatch<T>(r: BerResult<T>) -> BerResult<T> {
    match r {
        Err(BerError::TagMismatch) => Err(BerError::TagMismatch),
        r => r,
    }
}

impl Display for BerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        try!(write!(f, "{:?}", self));
        return Ok(());
    }
}

impl Error for BerError {
    fn description(&self) -> &str {
        match *self {
            BerError::TagMismatch => "Tag mismatch",
            BerError::Eof => "End of file",
            BerError::Extra => "Extra data in file",
            BerError::IntegerOverflow => "Integer overflow",
            BerError::Invalid => "Invalid data",
        }
    }
}

impl From<BerError> for io::Error {
    fn from(e: BerError) -> Self {
        return io::Error::new(io::ErrorKind::InvalidData, e);
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum BerMode {
    Ber, Cer, Der,
}

#[derive(Debug)]
enum TagState {
    None,
    Cached(Tag, PC),
    Implicit(PC, Option<usize>),
}

#[derive(Debug)]
pub struct BerReader<'a> {
    buf: &'a [u8],
    pos: usize,
    mode: BerMode,
    tag_state: TagState,
}

impl<'a> BerReader<'a> {
    fn new(buf: &'a [u8], mode: BerMode) -> Self {
        return BerReader {
            buf: buf,
            pos: 0,
            mode: mode,
            tag_state: TagState::None,
        };
    }
    fn read_u8(&mut self) -> BerResult<u8> {
        if self.pos < self.buf.len() {
            let ret = self.buf[self.pos];
            self.pos += 1;
            return Ok(ret);
        } else {
            return Err(BerError::Eof);
        }
    }
    pub fn remaining_buffer(&self) -> &'a [u8] {
        return &self.buf[self.pos..];
    }
    fn fetch_remaining_buffer(&mut self) -> &'a [u8] {
        let ret = &self.buf[self.pos..];
        self.pos = self.buf.len();
        return ret;
    }
    fn end_of_buf(&mut self) -> BerResult<()> {
        if self.pos != self.buf.len() {
            return Err(BerError::Extra);
        }
        return Ok(());
    }
    fn end_of_contents(&mut self) -> BerResult<()> {
        let (tag, pc) = match self.tag_state {
            TagState::None => try!(self.parse_identifier()),
            TagState::Cached(tag, pc) => (tag, pc),
            TagState::Implicit(_, _) => { return Err(BerError::Invalid); },
        };
        if tag != TAG_EOC || pc != PC::Primitive {
            return Err(BerError::Invalid);
        }
        let b = try!(self.read_u8());
        if b != 0 {
            return Err(BerError::Invalid);
        }
        return Ok(());
    }
    fn parse_identifier(&mut self) -> BerResult<(Tag, PC)> {
        let tagbyte = try!(self.read_u8());
        let tag_class = TAG_CLASSES[(tagbyte >> 6) as usize];
        let pc = PCS[((tagbyte >> 5) & 1) as usize];
        let mut tag_number = (tagbyte & 31) as u64;
        if tag_number == 31 {
            tag_number = 0;
            loop {
                let b = try!(self.read_u8()) as u64;
                let x =
                    try!(tag_number.checked_mul(128).ok_or(
                        BerError::IntegerOverflow));
                tag_number = x + (b & 127);
                if (b & 128) == 0 {
                    break;
                }
            }
            if tag_number < 31 {
                return Err(BerError::Invalid);
            }
        }
        let tag = Tag {
            tag_class: tag_class,
            tag_number: tag_number,
        };
        return Ok((tag, pc));
    }
    fn parse_length(&mut self) -> BerResult<Option<usize>> {
        let lbyte = try!(self.read_u8()) as usize;
        if lbyte == 128 {
            return Ok(None);
        }
        if lbyte == 255 {
            return Err(BerError::Invalid);
        }
        if (lbyte & 128) == 0 {
            return Ok(Some(lbyte));
        }
        let mut length : usize = 0;
        for _ in 0..(lbyte & 127) {
            let x = try!(length.checked_mul(256).ok_or(BerError::Eof));
            length = x + (try!(self.read_u8()) as usize);
        }
        if (self.mode == BerMode::Der || self.mode == BerMode::Cer)
                && length < 128 {
            return Err(BerError::Invalid);
        }
        return Ok(Some(length));
    }
    fn parse_general<T, F>
            (&mut self, tag: Tag, tag_type: TagType, fun: F) -> BerResult<T>
            where F: Fn(&mut Self, PC) -> BerResult<T> {
        let pc;
        let length_spec;
        match self.tag_state {
            TagState::None => {
                let (tag2, pc2) = try!(self.parse_identifier());
                if tag2 != tag {
                    self.tag_state = TagState::Cached(tag2, pc2);
                    return Err(BerError::TagMismatch);
                }
                pc = pc2;
                length_spec = try!(self.parse_length());
            },
            TagState::Cached(tag2, pc2) => {
                if tag2 != tag {
                    return Err(BerError::TagMismatch);
                }
                pc = pc2;
                length_spec = try!(self.parse_length());
            },
            TagState::Implicit(pc2, length_spec2) => {
                pc = pc2;
                length_spec = length_spec2;
            }
        };
        let old_buf = self.buf;
        if tag_type == TagType::Implicit {
            self.tag_state = TagState::Implicit(pc, length_spec);
        } else {
            self.tag_state = TagState::None;
        }
        match length_spec {
            Some(length) => {
                if self.mode == BerMode::Cer && pc != PC::Primitive {
                    return Err(BerError::Invalid);
                }
                let limit = self.pos+length;
                if old_buf.len() < limit {
                    return Err(BerError::Eof);
                }
                self.buf = &old_buf[..limit];
            },
            None => {
                if pc != PC::Constructed {
                    return Err(BerError::Invalid);
                }
                if self.mode == BerMode::Der {
                    return Err(BerError::Invalid);
                }
            },
        };
        let result = try!(wrap_tag_mismatch(fun(self, pc)));
        match length_spec {
            Some(_) => {
                try!(self.end_of_buf());
            },
            None => {
                try!(self.end_of_contents());
            },
        };
        self.buf = old_buf;
        return Ok(result);
    }
    pub fn parse_optional<T, F>(&mut self, fun: F) -> BerResult<Option<T>>
            where F: Fn(&mut Self) -> BerResult<T> {
        match fun(self) {
            Ok(result) => Ok(Some(result)),
            Err(BerError::TagMismatch) => Ok(None),
            Err(e) => Err(e),
        }
    }
    pub fn parse_default<T, F>(&mut self, default: T, fun: F) -> BerResult<T>
            where F: Fn(&mut Self) -> BerResult<T>, T: Eq {
        match fun(self) {
            Ok(result) => {
                if (self.mode == BerMode::Der || self.mode == BerMode::Cer) &&
                        result == default {
                    return Err(BerError::Invalid);
                }
                Ok(result)
            }
            Err(BerError::TagMismatch) => Ok(default),
            Err(e) => Err(e),
        }
    }
    pub fn parse_with_buffer<T, F>(&mut self, fun: F)
            -> BerResult<(T, &'a [u8])>
            where F: Fn(&mut Self) -> BerResult<T> {
        let old_pos = self.pos;
        let result = try!(fun(self));
        let new_pos = self.pos;
        let buf = &self.buf[old_pos..new_pos];
        return Ok((result, buf));
    }
    pub fn parse_tagged<T, F>
            (&mut self, tag: Tag, tag_type: TagType, fun: F)
            -> BerResult<T>
            where F: Fn(&mut Self) -> BerResult<T> {
        self.parse_general(tag, tag_type, |parser, pc| {
            if tag_type == TagType::Explicit && pc != PC::Constructed {
                return Err(BerError::Invalid);
            }
            fun(parser)
        })
    }
    pub fn from_buf<T, F>(buf: &'a [u8], mode: BerMode, fun: F)
            -> BerResult<T>
            where F: Fn(&mut Self) -> BerResult<T> {
        let mut parser = Self::new(buf, mode);
        let result = try!(wrap_tag_mismatch(fun(&mut parser)));
        try!(parser.end_of_buf());
        return Ok(result);
    }
    pub fn parse_sequence<T, F>(&mut self, fun: F) -> BerResult<T>
            where F: Fn(&mut Self) -> BerResult<T> {
        self.parse_general(TAG_SEQUENCE, TagType::Explicit, |parser, pc| {
            if pc != PC::Constructed {
                return Err(BerError::Invalid);
            }
            return wrap_tag_mismatch(fun(parser));
        })
    }
    pub fn parse_set<T, F>(&mut self, fun: F) -> BerResult<T>
            where F: Fn(&mut Self) -> BerResult<T> {
        self.parse_general(TAG_SET, TagType::Explicit, |parser, pc| {
            if pc != PC::Constructed {
                return Err(BerError::Invalid);
            }
            return wrap_tag_mismatch(fun(parser));
        })
    }
    pub fn parse<T:FromBer>(&mut self) -> BerResult<T> {
        return T::from_ber(self);
    }
}

pub trait FromBer: Sized + Eq + Hash {
    fn from_ber<'a>(parser: &mut BerReader<'a>) -> BerResult<Self>;
}

impl<T> FromBer for Vec<T> where T: Sized + Eq + Hash + FromBer {
    fn from_ber(parser: &mut BerReader) -> BerResult<Self> {
        parser.parse_sequence(|parser| {
            let mut ret = Vec::new();
            loop {
                match T::from_ber(parser) {
                    Ok(result) => {
                        ret.push(result);
                    },
                    Err(BerError::TagMismatch) => {
                        break;
                    },
                    Err(e) => {
                        return Err(e);
                    }
                };
            }
            return Ok(ret);
        })
    }
}

impl<T> FromBer for SetOf<T> where T: Sized + Eq + Hash + FromBer {
    fn from_ber<'a>(parser: &mut BerReader<'a>) -> BerResult<Self> {
        parser.parse_set(|parser| {
            let mut ret = SetOf::new();
            let mut old_buf : Option<&'a [u8]> = None;
            loop {
                let (result, buf) = try!(parser.parse_with_buffer(|parser| {
                    T::from_ber(parser)
                }));
                if parser.mode == BerMode::Der || parser.mode == BerMode::Cer {
                    match old_buf {
                        Some(old_buf) => {
                            match old_buf.iter().cmp(buf.iter()) {
                                Ordering::Less => {},
                                Ordering::Equal => {
                                    if old_buf.len() > buf.len() {
                                        return Err(BerError::Invalid);
                                    }
                                },
                                Ordering::Greater => {
                                    return Err(BerError::Invalid);
                                },
                            }
                        }
                        None => {},
                    }
                }
                old_buf = Some(buf);
                match T::from_ber(parser) {
                    Ok(result) => {
                        ret.vec.push(result);
                    },
                    Err(BerError::TagMismatch) => {
                        break;
                    },
                    Err(e) => {
                        return Err(e);
                    }
                };
            }
            return Ok(ret);
        })
    }
}

impl FromBer for i64 {
    fn from_ber(parser: &mut BerReader) -> BerResult<Self> {
        parser.parse_general(TAG_INTEGER, TagType::Explicit, |parser, pc| {
            if pc != PC::Primitive {
                return Err(BerError::Invalid);
            }
            let buf = parser.fetch_remaining_buffer();
            if buf.len() == 0 {
                return Err(BerError::Invalid);
            } else if buf.len() == 1 {
                return Ok(buf[0] as i8 as i64);
            }
            let mut x = ((buf[0] as i8 as i64) << 8) + (buf[1] as i64);
            if -128 <= x && x < 128 {
                return Err(BerError::Invalid);
            }
            if buf.len() > 8 {
                return Err(BerError::IntegerOverflow);
            }
            for &b in buf[2..].iter() {
                x = (x << 8) | (b as i64);
            }
            return Ok(x);
        })
    }
}

impl FromBer for () {
    fn from_ber(parser: &mut BerReader) -> BerResult<Self> {
        parser.parse_general(TAG_NULL, TagType::Explicit, |parser, pc| {
            if pc != PC::Primitive {
                return Err(BerError::Invalid);
            }
            let buf = parser.fetch_remaining_buffer();
            if buf.len() != 0 {
                return Err(BerError::Invalid);
            }
            return Ok(());
        })
    }
}

const TAG_CLASSES : [TagClass; 4] = [
    TagClass::Universal,
    TagClass::Application,
    TagClass::ContextSpecific,
    TagClass::Private,
];

const TAG_EOC : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 0,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
enum PC {
    Primitive = 0, Constructed = 1,
}

const PCS : [PC; 2] = [PC::Primitive, PC::Constructed];

impl FromBer for ObjectIdentifier {
    fn from_ber(parser: &mut BerReader) -> BerResult<Self> {
        parser.parse_general(TAG_OID, TagType::Explicit, |parser, pc| {
            if pc != PC::Primitive {
                return Err(BerError::Invalid);
            }
            let mut ids = Vec::new();
            let buf = parser.fetch_remaining_buffer();
            if buf.len() == 0 || buf[buf.len()-1] >= 128 {
                return Err(BerError::Invalid);
            }
            let mut pos = 0;
            let mut subid : u64 = 0;
            for &b in buf.iter() {
                if b == 128 {
                    return Err(BerError::Invalid);
                }
                subid = try!(subid.checked_mul(128)
                    .ok_or(BerError::IntegerOverflow)) + ((b & 127) as u64);
                if (b & 128) == 0 {
                    if ids.len() == 0 {
                        let id0 = if subid < 40 {
                            0
                        } else if subid < 80 {
                            1
                        } else {
                            2
                        };
                        let id1 = subid - 40 * id0;
                        ids.push(id0);
                        ids.push(id1);
                    } else {
                        ids.push(subid);
                    }
                    subid = 0;
                }
            }
            return Ok(Self::new(ids));
        })
    }
}
