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
}

impl Deref for PrintableString {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        return &self.string;
    }
}
