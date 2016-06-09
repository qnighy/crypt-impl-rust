// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

extern crate byteorder;

use self::byteorder::{BigEndian, ByteOrder};
use std::cmp;
use std::io::{Write, Result};

const K256 : [u32; 64] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
];

const K512 : [u64; 80] = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F,
    0xE9B5DBA58189DBBC, 0x3956C25BF348B538, 0x59F111F1B605D019,
    0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118, 0xD807AA98A3030242,
    0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235,
    0xC19BF174CF692694, 0xE49B69C19EF14AD2, 0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65, 0x2DE92C6F592B0275,
    0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F,
    0xBF597FC7BEEF0EE4, 0xC6E00BF33DA88FC2, 0xD5A79147930AA725,
    0x06CA6351E003826F, 0x142929670A0E6E70, 0x27B70A8546D22FFC,
    0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6,
    0x92722C851482353B, 0xA2BFE8A14CF10364, 0xA81A664BBC423001,
    0xC24B8B70D0F89791, 0xC76C51A30654BE30, 0xD192E819D6EF5218,
    0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99,
    0x34B0BCB5E19B48A8, 0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB,
    0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3, 0x748F82EE5DEFB2FC,
    0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915,
    0xC67178F2E372532B, 0xCA273ECEEA26619C, 0xD186B8C721C0C207,
    0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178, 0x06F067AA72176FBA,
    0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC,
    0x431D67C49C100D4C, 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A,
    0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
];

fn update256(hh: &mut [u32; 8], chunk: &[u8; 64]) {
    let mut w : [u32; 64] = [0; 64];
    for i in 0..16 {
        w[i] = BigEndian::read_u32(&chunk[i * 4 .. i * 4 + 4]);
    }
    for i in 16..64 {
        let s0 : u32 =
            w[i-15].rotate_right(7) ^
            w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
        let s1 : u32 =
            w[i-2].rotate_right(17) ^
            w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
        w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
    }
    let mut a : u32 = hh[0];
    let mut b : u32 = hh[1];
    let mut c : u32 = hh[2];
    let mut d : u32 = hh[3];
    let mut e : u32 = hh[4];
    let mut f : u32 = hh[5];
    let mut g : u32 = hh[6];
    let mut h : u32 = hh[7];
    for i in 0..64 {
        let s1 : u32 =
            e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch : u32 = (e & f) ^ (!e & g);
        let tmp1 : u32 = h.wrapping_add(s1).wrapping_add(ch)
            .wrapping_add(K256[i]).wrapping_add(w[i]);
        let s0 : u32 =
            a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj : u32 = (a & b) ^ (a & c) ^ (b & c);
        let tmp2 : u32 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(tmp1);
        d = c;
        c = b;
        b = a;
        a = tmp1.wrapping_add(tmp2);
    }
    hh[0] = hh[0].wrapping_add(a);
    hh[1] = hh[1].wrapping_add(b);
    hh[2] = hh[2].wrapping_add(c);
    hh[3] = hh[3].wrapping_add(d);
    hh[4] = hh[4].wrapping_add(e);
    hh[5] = hh[5].wrapping_add(f);
    hh[6] = hh[6].wrapping_add(g);
    hh[7] = hh[7].wrapping_add(h);
}

fn update512(hh: &mut [u64; 8], chunk: &[u8; 128]) {
    let mut w : [u64; 80] = [0; 80];
    for i in 0..16 {
        w[i] = BigEndian::read_u64(&chunk[i * 8 .. i * 8 + 8]);
    }
    for i in 16..80 {
        let s0 : u64 =
            w[i-15].rotate_right(1) ^
            w[i-15].rotate_right(8) ^ (w[i-15] >> 7);
        let s1 : u64 =
            w[i-2].rotate_right(19) ^
            w[i-2].rotate_right(61) ^ (w[i-2] >> 6);
        w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
    }
    let mut a : u64 = hh[0];
    let mut b : u64 = hh[1];
    let mut c : u64 = hh[2];
    let mut d : u64 = hh[3];
    let mut e : u64 = hh[4];
    let mut f : u64 = hh[5];
    let mut g : u64 = hh[6];
    let mut h : u64 = hh[7];
    for i in 0..80 {
        let s1 : u64 =
            e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch : u64 = (e & f) ^ (!e & g);
        let tmp1 : u64 = h.wrapping_add(s1).wrapping_add(ch)
            .wrapping_add(K512[i]).wrapping_add(w[i]);
        let s0 : u64 =
            a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj : u64 = (a & b) ^ (a & c) ^ (b & c);
        let tmp2 : u64 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(tmp1);
        d = c;
        c = b;
        b = a;
        a = tmp1.wrapping_add(tmp2);
    }
    hh[0] = hh[0].wrapping_add(a);
    hh[1] = hh[1].wrapping_add(b);
    hh[2] = hh[2].wrapping_add(c);
    hh[3] = hh[3].wrapping_add(d);
    hh[4] = hh[4].wrapping_add(e);
    hh[5] = hh[5].wrapping_add(f);
    hh[6] = hh[6].wrapping_add(g);
    hh[7] = hh[7].wrapping_add(h);
}

pub struct SHA224Writer {
    state: [u32; 8],
    position: u64,
    buf: [u8; 64],
    bufpos: usize,
}

pub struct SHA256Writer {
    state: [u32; 8],
    position: u64,
    buf: [u8; 64],
    bufpos: usize,
}

pub struct SHA384Writer {
    state: [u64; 8],
    position0: u64,
    position1: u64,
    buf: [u8; 128],
    bufpos: usize,
}

pub struct SHA512Writer {
    state: [u64; 8],
    position0: u64,
    position1: u64,
    buf: [u8; 128],
    bufpos: usize,
}

impl Copy for SHA224Writer {}
impl Clone for SHA224Writer {
    fn clone(&self) -> Self {
        return SHA224Writer {
            state: self.state,
            position: self.position,
            buf: self.buf,
            bufpos: self.bufpos
        };
    }
}

impl Copy for SHA256Writer {}
impl Clone for SHA256Writer {
    fn clone(&self) -> Self {
        return SHA256Writer {
            state: self.state,
            position: self.position,
            buf: self.buf,
            bufpos: self.bufpos
        };
    }
}

impl Copy for SHA384Writer {}
impl Clone for SHA384Writer {
    fn clone(&self) -> Self {
        return SHA384Writer {
            state: self.state,
            position0: self.position0,
            position1: self.position1,
            buf: self.buf,
            bufpos: self.bufpos
        };
    }
}

impl Copy for SHA512Writer {}
impl Clone for SHA512Writer {
    fn clone(&self) -> Self {
        return SHA512Writer {
            state: self.state,
            position0: self.position0,
            position1: self.position1,
            buf: self.buf,
            bufpos: self.bufpos
        };
    }
}

impl SHA224Writer {
    pub fn new() -> SHA224Writer {
        return SHA224Writer {
            state:
                [0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
                0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4],
            position: 0,
            buf: [0; 64],
            bufpos: 0,
        };
    }
    pub fn sum(&self) -> [u8; 28] {
        let mut state = self.state;
        let mut buf = self.buf;
        let buflen = buf.len();
        let bufpos = self.bufpos;
        buf[self.bufpos] = 0x80;
        for i in bufpos + 1 .. buflen { buf[i] = 0; }
        if bufpos + 1 > buflen - 8 {
            update256(&mut state, &buf);
            for i in 0 .. buflen { buf[i] = 0; }
        }
        BigEndian::write_u64(&mut buf[buflen - 8 ..], self.position);
        update256(&mut state, &buf);
        let mut hashbuf : [u8; 28] = [0; 28];
        for i in 0..7 {
            BigEndian::write_u32(
                &mut hashbuf[i * 4 .. i * 4 + 4], state[i]);
        }
        return hashbuf;
    }
}

impl SHA256Writer {
    pub fn new() -> SHA256Writer {
        return SHA256Writer {
            state:
                [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19],
            position: 0,
            buf: [0; 64],
            bufpos: 0,
        };
    }
    pub fn sum(&self) -> [u8; 32] {
        let mut state = self.state;
        let mut buf = self.buf;
        let buflen = buf.len();
        let bufpos = self.bufpos;
        buf[self.bufpos] = 0x80;
        for i in bufpos + 1 .. buflen { buf[i] = 0; }
        if bufpos + 1 > buflen - 8 {
            update256(&mut state, &buf);
            for i in 0 .. buflen { buf[i] = 0; }
        }
        BigEndian::write_u64(&mut buf[buflen - 8 ..], self.position);
        update256(&mut state, &buf);
        let mut hashbuf : [u8; 32] = [0; 32];
        for i in 0..8 {
            BigEndian::write_u32(
                &mut hashbuf[i * 4 .. i * 4 + 4], state[i]);
        }
        return hashbuf;
    }
}

impl SHA384Writer {
    pub fn new() -> SHA384Writer {
        return SHA384Writer {
            state:
                [0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17,
                0x152FECD8F70E5939, 0x67332667FFC00B31, 0x8EB44A8768581511,
                0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4],
            position0: 0,
            position1: 0,
            buf: [0; 128],
            bufpos: 0,
        };
    }
    pub fn sum(&self) -> [u8; 48] {
        let mut state = self.state;
        let mut buf = self.buf;
        let buflen = buf.len();
        let bufpos = self.bufpos;
        buf[self.bufpos] = 0x80;
        for i in bufpos + 1 .. buflen { buf[i] = 0; }
        if bufpos + 1 > buflen - 16 {
            update512(&mut state, &buf);
            for i in 0 .. buflen { buf[i] = 0; }
        }
        BigEndian::write_u64(
            &mut buf[buflen - 16 .. buflen - 8], self.position1);
        BigEndian::write_u64(&mut buf[buflen - 8 ..], self.position0);
        update512(&mut state, &buf);
        let mut hashbuf : [u8; 48] = [0; 48];
        for i in 0..6 {
            BigEndian::write_u64(
                &mut hashbuf[i * 8 .. i * 8 + 8], state[i]);
        }
        return hashbuf;
    }
}

impl SHA512Writer {
    pub fn new() -> SHA512Writer {
        return SHA512Writer {
            state:
                [0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B,
                0xA54FF53A5F1D36F1, 0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
                0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179],
            position0: 0,
            position1: 0,
            buf: [0; 128],
            bufpos: 0,
        };
    }
    pub fn sum(&self) -> [u8; 64] {
        let mut state = self.state;
        let mut buf = self.buf;
        let buflen = buf.len();
        let bufpos = self.bufpos;
        buf[self.bufpos] = 0x80;
        for i in bufpos + 1 .. buflen { buf[i] = 0; }
        if bufpos + 1 > buflen - 16 {
            update512(&mut state, &buf);
            for i in 0 .. buflen { buf[i] = 0; }
        }
        BigEndian::write_u64(
            &mut buf[buflen - 16 .. buflen - 8], self.position1);
        BigEndian::write_u64(&mut buf[buflen - 8 ..], self.position0);
        update512(&mut state, &buf);
        let mut hashbuf : [u8; 64] = [0; 64];
        for i in 0..8 {
            BigEndian::write_u64(
                &mut hashbuf[i * 8 .. i * 8 + 8], state[i]);
        }
        return hashbuf;
    }
}

impl Write for SHA224Writer {
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
                update256(&mut self.state, &self.buf);
                self.bufpos -= self.buf.len();
            }
        }
        return Ok(orig_len);
    }
    fn flush(&mut self) -> Result<()> {
        return Ok(());
    }
}

impl Write for SHA256Writer {
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
                update256(&mut self.state, &self.buf);
                self.bufpos -= self.buf.len();
            }
        }
        return Ok(orig_len);
    }
    fn flush(&mut self) -> Result<()> {
        return Ok(());
    }
}

impl Write for SHA384Writer {
    fn write(&mut self, mut buf: &[u8]) -> Result<usize> {
        let orig_len = buf.len();
        while buf.len() > 0 {
            let wrsize = cmp::min(self.buf.len() - self.bufpos, buf.len());
            self.buf[self.bufpos .. self.bufpos + wrsize]
                .clone_from_slice(&buf[0 .. wrsize]);
            buf = &buf[wrsize ..];
            match self.position0.checked_add((wrsize * 8) as u64) {
                Some(new_position) => {
                    self.position0 = new_position;
                }
                None => {
                    self.position0 =
                        self.position0.wrapping_add((wrsize * 8) as u64);
                    self.position1 += 1;
                }
            }
            self.bufpos += wrsize;
            if self.bufpos >= self.buf.len() {
                update512(&mut self.state, &self.buf);
                self.bufpos -= self.buf.len();
            }
        }
        return Ok(orig_len);
    }
    fn flush(&mut self) -> Result<()> {
        return Ok(());
    }
}

impl Write for SHA512Writer {
    fn write(&mut self, mut buf: &[u8]) -> Result<usize> {
        let orig_len = buf.len();
        while buf.len() > 0 {
            let wrsize = cmp::min(self.buf.len() - self.bufpos, buf.len());
            self.buf[self.bufpos .. self.bufpos + wrsize]
                .clone_from_slice(&buf[0 .. wrsize]);
            buf = &buf[wrsize ..];
            match self.position0.checked_add((wrsize * 8) as u64) {
                Some(new_position) => {
                    self.position0 = new_position;
                }
                None => {
                    self.position0 =
                        self.position0.wrapping_add((wrsize * 8) as u64);
                    self.position1 += 1;
                }
            }
            self.bufpos += wrsize;
            if self.bufpos >= self.buf.len() {
                update512(&mut self.state, &self.buf);
                self.bufpos -= self.buf.len();
            }
        }
        return Ok(orig_len);
    }
    fn flush(&mut self) -> Result<()> {
        return Ok(());
    }
}
