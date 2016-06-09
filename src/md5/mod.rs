// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

extern crate byteorder;

use self::byteorder::{LittleEndian, ByteOrder};
use std::cmp;
use std::io::{Write, Result};

const S : [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
const K : [u32; 64] = [
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
];

fn update(hh: &mut [u32; 4], chunk: &[u8; 64]) {
    let mut m : [u32; 16] = [0; 16];
    for i in 0..16 {
        m[i] = LittleEndian::read_u32(&chunk[i * 4 .. i * 4 + 4]);
    }
    let mut a : u32 = hh[0];
    let mut b : u32 = hh[1];
    let mut c : u32 = hh[2];
    let mut d : u32 = hh[3];
    for i in 0..64 {
        let f : u32;
        let g : usize;
        if i < 16 {
            f = (b & c) | (!b & d);
            g = i;
        } else if i < 32 {
            f = (d & b) | (!d & c);
            g = (5 * i + 1) % 16;
        } else if i < 48 {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | !d);
            g = 7 * i % 16;
        }
        let tmp = d;
        d = c;
        c = b;
        b = b.wrapping_add(
            (a.wrapping_add(f)
             .wrapping_add(K[i]).wrapping_add(m[g])).rotate_left(S[i]));
        a = tmp;
    }
    hh[0] = hh[0].wrapping_add(a);
    hh[1] = hh[1].wrapping_add(b);
    hh[2] = hh[2].wrapping_add(c);
    hh[3] = hh[3].wrapping_add(d);
}

pub struct MD5Writer {
    state: [u32; 4],
    position: u64,
    buf: [u8; 64],
    bufpos: usize,
}

impl Copy for MD5Writer {}
impl Clone for MD5Writer {
    fn clone(&self) -> Self {
        return MD5Writer {
            state: self.state,
            position: self.position,
            buf: self.buf,
            bufpos: self.bufpos
        };
    }
}

impl MD5Writer {
    pub fn new() -> MD5Writer {
        return MD5Writer {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476],
            position: 0,
            buf: [0; 64],
            bufpos: 0,
        };
    }
    pub fn sum(&self) -> [u8; 16] {
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
        LittleEndian::write_u64(&mut buf[buflen - 8 ..], self.position);
        update(&mut state, &buf);
        let mut hashbuf : [u8; 16] = [0; 16];
        for i in 0..4 {
            LittleEndian::write_u32(
                &mut hashbuf[i * 4 .. i * 4 + 4], state[i]);
        }
        return hashbuf;
    }
}

impl Write for MD5Writer {
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
