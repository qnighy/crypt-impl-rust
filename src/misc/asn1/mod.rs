// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

pub mod ber;

use std::ops::{Deref, DerefMut};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TagClass {
    Universal, Application, ContextSpecific, Private,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Tag {
    pub tag_class: TagClass,
    pub tag_number: u64,
}

pub const TAG_BOOLEAN : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 1,
};

pub const TAG_INTEGER : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 2,
};

pub const TAG_BITSTRING : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 3,
};

pub const TAG_OCTETSTRING : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 4,
};

pub const TAG_NULL : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 5,
};

pub const TAG_OID : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 6,
};

pub const TAG_UTF8STRING : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 12,
};

pub const TAG_SEQUENCE : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 16,
};

pub const TAG_SET : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 17,
};

pub const TAG_PRINTABLESTRING : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 19,
};

pub const TAG_UTCTIME : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 23,
};

impl Tag {
    pub fn application(tag_number: u64) -> Tag {
        return Tag {
            tag_class: TagClass::Application,
            tag_number: tag_number,
        }
    }
    pub fn context(tag_number: u64) -> Tag {
        return Tag {
            tag_class: TagClass::ContextSpecific,
            tag_number: tag_number,
        }
    }
    pub fn private(tag_number: u64) -> Tag {
        return Tag {
            tag_class: TagClass::Private,
            tag_number: tag_number,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TagType {
    Explicit, Implicit,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct BitString {
    unused_bits: usize,
    buf: Vec<u8>,
}

impl BitString {
    pub fn new() -> Self {
        return BitString {
            unused_bits: 0,
            buf: Vec::new(),
        };
    }
    pub fn from_buf(unused_bits : usize, buf: Vec<u8>) -> Self {
        return BitString {
            unused_bits: unused_bits,
            buf: buf,
        };
    }
    pub fn push(&mut self, b: bool) {
        if self.unused_bits == 0 {
            self.buf.push(0);
            self.unused_bits = 8;
        }
        let last = self.buf.last_mut().unwrap();
        self.unused_bits -= 1;
        *last = *last | ((b as u8) << self.unused_bits);
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SetOf<T> {
    pub vec: Vec<T>,
}

impl<T> SetOf<T> {
    pub fn new() -> Self {
        SetOf {
            vec: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ObjectIdentifier {
    ids: Vec<u64>,
}

use std::slice::Iter;
impl ObjectIdentifier {
    pub fn new(ids: Vec<u64>) -> Self {
        return ObjectIdentifier {
            ids: ids,
        };
    }
    pub fn iter(&self) -> Iter<u64> {
        self.ids.iter()
    }
}

impl Deref for ObjectIdentifier {
    type Target = [u64];
    fn deref(&self) -> &Self::Target {
        return &self.ids;
    }
}

impl DerefMut for ObjectIdentifier {
    fn deref_mut(&mut self) -> &mut Self::Target {
        return &mut self.ids;
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PrintableString {
    string: String,
}

impl PrintableString {
    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        for &b in bytes.iter() {
            let ok =
                (b'0' <= b && b <= b'9') ||
                (b'A' <= b && b <= b'Z') ||
                (b'a' <= b && b <= b'z') ||
                b == b' ' || b == b'\'' || b == b'(' || b == b')' ||
                b == b'+' || b == b',' || b == b'-' || b == b'.' ||
                b == b'/' || b == b':' || b == b'=' || b == b'?';
            if !ok {
                return None;
            }
        }
        return Some(PrintableString {
            string: String::from_utf8(bytes).unwrap(),
        });
    }
}

impl Deref for PrintableString {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        return &self.string;
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UtcTime {
    bytes: Vec<u8>,
}

impl UtcTime {
    pub fn new(bytes: Vec<u8>) -> Self {
        return UtcTime {
            bytes: bytes,
        };
    }
}
