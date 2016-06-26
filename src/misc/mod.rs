// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

extern crate byteorder;

use std::io::{self,Read,Write,Seek};
use self::byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt, NetworkEndian};

pub struct LengthMarkR16 {
    end: u64,
}

pub struct LengthMarkR24 {
    end: u64,
}

pub struct LengthMarkW16 {
    begin: u64,
}

pub struct LengthMarkW24 {
    begin: u64,
}

impl LengthMarkR16 {
    pub fn new<R:Read+Seek>(src: &mut R) -> io::Result<Self> {
        let length = try!(src.read_u16::<NetworkEndian>());
        let begin = try!(src.seek(io::SeekFrom::Current(0)));
        return Ok(LengthMarkR16 {
            end: begin + (length as u64),
        });
    }
    pub fn is_remaining<R:Read+Seek>(&self, src: &mut R) -> io::Result<bool> {
        let current = try!(src.seek(io::SeekFrom::Current(0)));
        return Ok(current < self.end);
    }
    pub fn check<R:Read+Seek>(self, src: &mut R) -> io::Result<()> {
        let current = try!(src.seek(io::SeekFrom::Current(0)));
        if current != self.end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData, "Invalid Length"));
        }
        return Ok(());
    }
}

impl LengthMarkR24 {
    pub fn new<R:Read+Seek>(src: &mut R) -> io::Result<Self> {
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
    pub fn is_remaining<R:Read+Seek>(&self, src: &mut R) -> io::Result<bool> {
        let current = try!(src.seek(io::SeekFrom::Current(0)));
        return Ok(current < self.end);
    }
    pub fn check<R:Read+Seek>(self, src: &mut R) -> io::Result<()> {
        let current = try!(src.seek(io::SeekFrom::Current(0)));
        if current != self.end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData, "Invalid Length"));
        }
        return Ok(());
    }
}

impl LengthMarkW16 {
    pub fn new<W:Write+Seek>(dest: &mut W) -> io::Result<Self> {
        let begin = try!(dest.seek(io::SeekFrom::Current(0)));
        try!(dest.write_u16::<NetworkEndian>(0));
        return Ok(LengthMarkW16 {
            begin: begin,
        });
    }
    pub fn record<W:Write+Seek>(self, dest: &mut W) -> io::Result<()> {
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
    pub fn new<W:Write+Seek>(dest: &mut W) -> io::Result<Self> {
        let begin = try!(dest.seek(io::SeekFrom::Current(0)));
        try!(dest.write_u8(0));
        try!(dest.write_u8(0));
        try!(dest.write_u8(0));
        return Ok(LengthMarkW24 {
            begin: begin,
        });
    }
    pub fn record<W:Write+Seek>(self, dest: &mut W) -> io::Result<()> {
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
