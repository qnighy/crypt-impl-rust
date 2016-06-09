// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

extern crate byteorder;

use self::byteorder::{BigEndian, ByteOrder};
use std::cmp;
use std::io::{Write, Result};

fn update(hh: &mut [u32; 5], chunk: &[u8; 64]) {
    let mut w : [u32; 80] = [0; 80];
    for i in 0..16 {
        w[i] = BigEndian::read_u32(&chunk[i * 4 .. i * 4 + 4]);
    }
    for i in 16..80 {
        w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
    }
    let mut a : u32 = hh[0];
    let mut b : u32 = hh[1];
    let mut c : u32 = hh[2];
    let mut d : u32 = hh[3];
    let mut e : u32 = hh[4];
    for i in 0..80 {
        let f : u32;
        let k : u32;
        if i < 20 {
            f = (b & c) | (!b & d);
            k = 0x5A827999;
        } else if i < 40 {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if i < 60 {
            f = (b & c) ^ (b & d) ^ (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        let tmp = a.rotate_left(5).wrapping_add(f)
            .wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = tmp;
    }
    hh[0] = hh[0].wrapping_add(a);
    hh[1] = hh[1].wrapping_add(b);
    hh[2] = hh[2].wrapping_add(c);
    hh[3] = hh[3].wrapping_add(d);
    hh[4] = hh[4].wrapping_add(e);
}

pub struct SHA1Writer {
    state: [u32; 5],
    position: u64,
    buf: [u8; 64],
    bufpos: usize,
}

impl Copy for SHA1Writer {}
impl Clone for SHA1Writer {
    fn clone(&self) -> Self {
        return SHA1Writer {
            state: self.state,
            position: self.position,
            buf: self.buf,
            bufpos: self.bufpos
        };
    }
}

impl SHA1Writer {
    pub fn new() -> SHA1Writer {
        return SHA1Writer {
            state:
                [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            position: 0,
            buf: [0; 64],
            bufpos: 0,
        };
    }
    pub fn sum(&self) -> [u8; 20] {
        let mut state = self.state;
        let mut buf = self.buf;
        let buflen = buf.len();
        let bufpos = self.bufpos;
        buf[self.bufpos] = 0x80;
        for i in bufpos + 1 .. buflen { buf[i] = 0; }
        if bufpos + 1 > buflen - 8 {
            update(&mut state, &buf);
            for i in 0 .. buflen { buf[i] = 0; }
        }
        BigEndian::write_u64(&mut buf[buflen - 8 ..], self.position);
        update(&mut state, &buf);
        let mut hashbuf : [u8; 20] = [0; 20];
        for i in 0..5 {
            BigEndian::write_u32(
                &mut hashbuf[i * 4 .. i * 4 + 4], state[i]);
        }
        return hashbuf;
    }
}

impl Write for SHA1Writer {
    fn write(&mut self, mut buf: &[u8]) -> Result<usize> {
        let orig_len = buf.len();
        while buf.len() > 0 {
            let wrsize = cmp::min(self.buf.len() - self.bufpos, buf.len());
            self.buf[self.bufpos .. self.bufpos + wrsize]
                .clone_from_slice(&buf[0 .. wrsize]);
            buf = &buf[wrsize ..];
            self.position += (wrsize * 8) as u64;
            self.bufpos += wrsize;
            if self.bufpos >= self.buf.len() {
                update(&mut self.state, &self.buf);
                self.bufpos -= self.buf.len();
            }
        }
        return Ok(orig_len);
    }
    fn flush(&mut self) -> Result<()> {
        return Ok(());
    }
}
