// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use std::io::{self,Read,Write,Seek};
use std::marker::PhantomData;
use byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt, NetworkEndian};

pub trait LengthWriter {
    fn skip(vec: &mut Vec<u8>);
    fn write(vec: &mut Vec<u8>, position: usize);
}

pub enum Length16 {}
pub enum Length24 {}

pub struct PositionVec<'a, L:LengthWriter> {
    vec: &'a mut Vec<u8>,
    position: usize,
    phantom: PhantomData<L>,
}

pub struct LengthMarkR16 {
    end: u64,
}

pub struct LengthMarkR24 {
    end: u64,
}

impl<'a, L:LengthWriter> PositionVec<'a, L> {
    pub fn new(vec: &'a mut Vec<u8>) -> PositionVec<'a, L> {
        L::skip(vec);
        let position = vec.len();
        return PositionVec {
            vec: vec,
            position: position,
            phantom: PhantomData,
        };
    }
    pub fn get(&mut self) -> &mut Vec<u8> {
        return self.vec;
    }
}

impl<'a, L:LengthWriter> Drop for PositionVec<'a, L> {
    fn drop(&mut self) {
        L::write(self.vec, self.position);
    }
}

impl<'a, L:LengthWriter> Write for PositionVec<'a, L> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        return self.vec.write(buf);
    }
    fn flush(&mut self) -> io::Result<()> {
        return self.vec.flush();
    }
}

impl LengthWriter for Length16 {
    fn skip(vec: &mut Vec<u8>) {
        vec.extend_from_slice(&[0, 0]);
    }
    fn write(vec: &mut Vec<u8>, position: usize) {
        let length = vec.len() - position;
        assert!(length < 65536);
        vec[position-2] = (length >> 8) as u8;
        vec[position-1] = (length >> 0) as u8;
    }
}

impl LengthWriter for Length24 {
    fn skip(vec: &mut Vec<u8>) {
        vec.extend_from_slice(&[0, 0, 0]);
    }
    fn write(vec: &mut Vec<u8>, position: usize) {
        let length = vec.len() - position;
        assert!(length < 16777216);
        vec[position-3] = (length >> 16) as u8;
        vec[position-2] = (length >> 8) as u8;
        vec[position-1] = (length >> 0) as u8;
    }
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
