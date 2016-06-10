// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

extern crate byteorder;

use self::byteorder::{LittleEndian, ByteOrder};
use std::cmp;
use std::io::{Write, Result};

const RC : [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];
const R : [u32; 25] = [
    0, 44, 43, 21, 14, 28, 20, 3, 45, 61, 1, 6, 25,
    8, 18, 27, 36, 10, 15, 56, 62, 55, 39, 41, 2,
];

fn update(hh: &mut [u64; 25]) {
    for rc in RC.iter() {
        let mut c : [u64; 5] = [0; 5];
        for x in 0..5 {
            c[x] = hh[x] ^ hh[5+x] ^ hh[10+x] ^ hh[15+x] ^ hh[20+x];
        }
        for x in 0..5 {
            let d = c[(x+4)%5] ^ c[(x+1)%5].rotate_left(1);
            for y in 0..5 {
                hh[5*y+x] ^= d;
            }
        }
        let mut b : [u64; 25] = [0; 25];
        for y in 0..5 {
            for x in 0..5 {
                b[5*y+x] = hh[5*x+(3*y+x)%5].rotate_left(R[5*y+x]);
            }
        }

        for y in 0..5 {
            for x in 0..5 {
                hh[5*y+x] = b[5*y+x] ^ (!b[5*y+(x+1)%5] & b[5*y+(x+2)%5]);
            }
        }
        hh[0] ^= *rc;
    }
}
fn absorb(hh: &mut [u64; 25], block: &[u8]) {
    for i in 0 .. (block.len() / 8) {
        hh[i] ^= LittleEndian::read_u64(&block[i * 8 .. i * 8 + 8]);
    }
    update(hh);
}
fn squeeze_last(hh: &mut [u64; 25], block: &mut [u8]) {
    for i in 0 .. (block.len() / 8) {
        LittleEndian::write_u64(&mut block[i * 8 .. i * 8 + 8], hh[i]);
    }
}

pub struct SHA3B224Writer {
    state: [u64; 25],
    buf: [u8; 144],
    bufpos: usize,
}

pub struct SHA3B256Writer {
    state: [u64; 25],
    buf: [u8; 136],
    bufpos: usize,
}

pub struct SHA3B384Writer {
    state: [u64; 25],
    buf: [u8; 104],
    bufpos: usize,
}

pub struct SHA3B512Writer {
    state: [u64; 25],
    buf: [u8; 72],
    bufpos: usize,
}

impl Copy for SHA3B224Writer {}
impl Clone for SHA3B224Writer {
    fn clone(&self) -> Self {
        return SHA3B224Writer {
            state: self.state,
            buf: self.buf,
            bufpos: self.bufpos
        };
    }
}

impl Copy for SHA3B256Writer {}
impl Clone for SHA3B256Writer {
    fn clone(&self) -> Self {
        return SHA3B256Writer {
            state: self.state,
            buf: self.buf,
            bufpos: self.bufpos
        };
    }
}

impl Copy for SHA3B384Writer {}
impl Clone for SHA3B384Writer {
    fn clone(&self) -> Self {
        return SHA3B384Writer {
            state: self.state,
            buf: self.buf,
            bufpos: self.bufpos
        };
    }
}

impl Copy for SHA3B512Writer {}
impl Clone for SHA3B512Writer {
    fn clone(&self) -> Self {
        return SHA3B512Writer {
            state: self.state,
            buf: self.buf,
            bufpos: self.bufpos
        };
    }
}

impl SHA3B224Writer {
    pub fn new() -> SHA3B224Writer {
        return SHA3B224Writer {
            state: [0; 25],
            buf: [0; 144],
            bufpos: 0,
        };
    }
    pub fn sum(&self) -> [u8; 28] {
        let mut state = self.state;
        let mut buf = self.buf;
        let buflen = buf.len();
        let bufpos = self.bufpos;
        buf[bufpos] = 0x06;
        for i in bufpos + 1 .. buflen { buf[i] = 0; }
        buf[buflen - 1] ^= 0x80;
        absorb(&mut state, &buf);
        let mut hashbuf : [u8; 28] = [0; 28];
        squeeze_last(&mut state, &mut hashbuf);
        return hashbuf;
    }
}

impl SHA3B256Writer {
    pub fn new() -> SHA3B256Writer {
        return SHA3B256Writer {
            state: [0; 25],
            buf: [0; 136],
            bufpos: 0,
        };
    }
    pub fn sum(&self) -> [u8; 32] {
        let mut state = self.state;
        let mut buf = self.buf;
        let buflen = buf.len();
        let bufpos = self.bufpos;
        buf[bufpos] = 0x06;
        for i in bufpos + 1 .. buflen { buf[i] = 0; }
        buf[buflen - 1] ^= 0x80;
        absorb(&mut state, &buf);
        let mut hashbuf : [u8; 32] = [0; 32];
        squeeze_last(&mut state, &mut hashbuf);
        return hashbuf;
    }
}

impl SHA3B384Writer {
    pub fn new() -> SHA3B384Writer {
        return SHA3B384Writer {
            state: [0; 25],
            buf: [0; 104],
            bufpos: 0,
        };
    }
    pub fn sum(&self) -> [u8; 48] {
        let mut state = self.state;
        let mut buf = self.buf;
        let buflen = buf.len();
        let bufpos = self.bufpos;
        buf[bufpos] = 0x06;
        for i in bufpos + 1 .. buflen { buf[i] = 0; }
        buf[buflen - 1] ^= 0x80;
        absorb(&mut state, &buf);
        let mut hashbuf : [u8; 48] = [0; 48];
        squeeze_last(&mut state, &mut hashbuf);
        return hashbuf;
    }
}

impl SHA3B512Writer {
    pub fn new() -> SHA3B512Writer {
        return SHA3B512Writer {
            state: [0; 25],
            buf: [0; 72],
            bufpos: 0,
        };
    }
    pub fn sum(&self) -> [u8; 64] {
        let mut state = self.state;
        let mut buf = self.buf;
        let buflen = buf.len();
        let bufpos = self.bufpos;
        buf[bufpos] = 0x06;
        for i in bufpos + 1 .. buflen { buf[i] = 0; }
        buf[buflen - 1] ^= 0x80;
        absorb(&mut state, &buf);
        let mut hashbuf : [u8; 64] = [0; 64];
        squeeze_last(&mut state, &mut hashbuf);
        return hashbuf;
    }
}

impl Write for SHA3B224Writer {
    fn write(&mut self, mut buf: &[u8]) -> Result<usize> {
        let orig_len = buf.len();
        while buf.len() > 0 {
            let wrsize = cmp::min(self.buf.len() - self.bufpos, buf.len());
            self.buf[self.bufpos .. self.bufpos + wrsize]
                .clone_from_slice(&buf[0 .. wrsize]);
            buf = &buf[wrsize ..];
            self.bufpos += wrsize;
            if self.bufpos >= self.buf.len() {
                absorb(&mut self.state, &self.buf);
                self.bufpos -= self.buf.len();
            }
        }
        return Ok(orig_len);
    }
    fn flush(&mut self) -> Result<()> {
        return Ok(());
    }
}

impl Write for SHA3B256Writer {
    fn write(&mut self, mut buf: &[u8]) -> Result<usize> {
        let orig_len = buf.len();
        while buf.len() > 0 {
            let wrsize = cmp::min(self.buf.len() - self.bufpos, buf.len());
            self.buf[self.bufpos .. self.bufpos + wrsize]
                .clone_from_slice(&buf[0 .. wrsize]);
            buf = &buf[wrsize ..];
            self.bufpos += wrsize;
            if self.bufpos >= self.buf.len() {
                absorb(&mut self.state, &self.buf);
                self.bufpos -= self.buf.len();
            }
        }
        return Ok(orig_len);
    }
    fn flush(&mut self) -> Result<()> {
        return Ok(());
    }
}

impl Write for SHA3B384Writer {
    fn write(&mut self, mut buf: &[u8]) -> Result<usize> {
        let orig_len = buf.len();
        while buf.len() > 0 {
            let wrsize = cmp::min(self.buf.len() - self.bufpos, buf.len());
            self.buf[self.bufpos .. self.bufpos + wrsize]
                .clone_from_slice(&buf[0 .. wrsize]);
            buf = &buf[wrsize ..];
            self.bufpos += wrsize;
            if self.bufpos >= self.buf.len() {
                absorb(&mut self.state, &self.buf);
                self.bufpos -= self.buf.len();
            }
        }
        return Ok(orig_len);
    }
    fn flush(&mut self) -> Result<()> {
        return Ok(());
    }
}

impl Write for SHA3B512Writer {
    fn write(&mut self, mut buf: &[u8]) -> Result<usize> {
        let orig_len = buf.len();
        while buf.len() > 0 {
            let wrsize = cmp::min(self.buf.len() - self.bufpos, buf.len());
            self.buf[self.bufpos .. self.bufpos + wrsize]
                .clone_from_slice(&buf[0 .. wrsize]);
            buf = &buf[wrsize ..];
            self.bufpos += wrsize;
            if self.bufpos >= self.buf.len() {
                absorb(&mut self.state, &self.buf);
                self.bufpos -= self.buf.len();
            }
        }
        return Ok(orig_len);
    }
    fn flush(&mut self) -> Result<()> {
        return Ok(());
    }
}
