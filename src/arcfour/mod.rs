// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use std::io::{Read, Write, Result};

pub struct Arcfour {
    s: [u8; 256],
    pi: usize,
    pj: usize,
}

pub struct ArcfourReader<R> {
    inner: R,
    prng: Arcfour,
}

pub struct ArcfourWriter<W> {
    inner: W,
    prng: Arcfour,
}

impl Arcfour {
    fn schedule(&mut self, key: &[u8]) {
        for i in 0..256 {
            self.s[i] = i as u8;
        }
        let mut j : usize = 0;
        if key.len() == 0 {
            for i in 0..256 {
                j = (j + self.s[i] as usize) % 256;
                self.s.swap(i, j);
            }
        } else {
            for i in 0..256 {
                j = (j + self.s[i] as usize +
                     key[i % key.len()] as usize) % 256;
                self.s.swap(i, j);
            }
        }
    }
    fn generate(&mut self) -> u8 {
        let i = (self.pi + 1) % 256;
        let j = (self.pj + self.s[i] as usize) % 256;
        self.pi = i;
        self.pj = j;
        self.s.swap(i, j);
        return self.s[(self.s[i] as usize + self.s[j] as usize) % 256];
    }
    pub fn new(key: &[u8]) -> Arcfour {
        let mut ret = Arcfour {
            s: [0; 256],
            pi: 0,
            pj: 0,
        };
        ret.schedule(key);
        return ret;
    }
}

impl Read for Arcfour {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let len = buf.len();
        for elem in buf {
            *elem = self.generate();
        }
        return Ok(len);
    }
}

impl<R> ArcfourReader<R> {
    pub fn new(inner: R, key: &[u8]) -> ArcfourReader<R> {
        return ArcfourReader {
            inner: inner,
            prng: Arcfour::new(key)
        };
    }
}

impl<R:Read> Read for ArcfourReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.inner.read(buf) {
            Ok(len) => {
                for elem in buf[0..len].iter_mut() {
                    *elem = *elem ^ self.prng.generate();
                }
                return Ok(len);
            }
            Err(err) => return Err(err)
        }
    }
}

impl<W> ArcfourWriter<W> {
    pub fn new(inner: W, key: &[u8]) -> ArcfourWriter<W> {
        return ArcfourWriter {
            inner: inner,
            prng: Arcfour::new(key)
        };
    }
}

impl<W:Write> Write for ArcfourWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut wsize : usize = 0;
        for elem in buf {
            match self.inner.write(&[*elem ^ self.prng.generate()]) {
                Ok(n) => {
                    if n == 0 { return Ok(wsize); }
                    wsize += n;
                }
                Err(e) => { return Err(e); }
            }
        }
        return Ok(wsize);
    }
    fn flush(&mut self) -> Result<()> {
        return self.inner.flush();
    }
}
