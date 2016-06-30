// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

pub mod asn1;

use std::io::{self,Read,Write,Cursor};
use std::marker::PhantomData;
use byteorder::{ByteOrder, ReadBytesExt, NetworkEndian};

pub trait LengthWriter {
    fn skip(vec: &mut Vec<u8>);
    fn write(vec: &mut Vec<u8>, position: usize);
}

pub trait LengthReader {
    fn read(buf: &mut Cursor<&[u8]>) -> io::Result<usize>;
}

pub enum Length16 {}
pub enum Length24 {}

pub struct PositionVec<'a, L> {
    vec: &'a mut Vec<u8>,
    position: usize,
    phantom: PhantomData<L>,
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
    pub fn finalize(self) {
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

// impl<'a, L> Drop for PositionVec<'a, L> {
//     fn drop(&mut self) {
//         panic!("Finalize PositionVec manually!");
//     }
// }

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

pub trait OnMemoryRead<'a>: Read {
    fn read_buf_exact(&mut self, len: usize) -> &'a [u8];
    fn remaining(&self) -> usize;
    fn is_remaining(&self) -> bool {
        return self.remaining() > 0;
    }
    fn check_remaining(&self) -> io::Result<()> {
        if self.is_remaining() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData, "Invalid Length"));
        } else {
            return Ok(());
        }
    }
    fn read_buf_u16sized(&mut self, minlen: usize, maxlen: usize)
            -> io::Result<&'a [u8]> {
        let length = try!(self.read_u16::<NetworkEndian>()) as usize;
        if length < minlen || maxlen < length || self.remaining() < length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData, "Invalid Length"));
        }
        return Ok(self.read_buf_exact(length));
    }
    fn read_buf_u24sized(&mut self, minlen: usize, maxlen: usize)
            -> io::Result<&'a [u8]> {
        let length = {
            let length0 = try!(self.read_u8()) as usize;
            let length1 = try!(self.read_u8()) as usize;
            let length2 = try!(self.read_u8()) as usize;
            (length0 << 16) | (length1 << 8) | length2
        };
        if length < minlen || maxlen < length || self.remaining() < length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData, "Invalid Length"));
        }
        return Ok(self.read_buf_exact(length));
    }
}

impl<'a> OnMemoryRead<'a> for Cursor<&'a [u8]> {
    fn read_buf_exact(&mut self, len: usize) -> &'a [u8] {
        let position = self.position() as usize;
        let ret = &self.get_ref()[position .. position+len];
        self.set_position((position+len) as u64);
        return ret;
    }
    fn remaining(&self) -> usize {
        return self.get_ref().len() - (self.position() as usize);
    }
}
