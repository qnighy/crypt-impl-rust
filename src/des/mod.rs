// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

extern crate byteorder;

use self::byteorder::{BigEndian, ByteOrder};
// use std::io::{Read, Write, Result};
use std::iter::Iterator;

pub struct DES {
    subkeys: [u64; 16],
}
pub struct TDES {
    des1: DES,
    des2: DES,
    des3: DES,
}

impl DES {
    pub fn new(key: &[u8]) -> DES {
        let mut ret = DES { subkeys: [0; 16] };
        ret.schedule(BigEndian::read_u64(key));
        return ret;
    }
    pub fn encrypt(&self, block: &mut [u8]) {
        let data = BigEndian::read_u64(block);
        let data = permute64(data, &IP);
        let mut data_left : u32 = (data >> 32) as u32;
        let mut data_right : u32 = (data & ((1 << 32) - 1)) as u32;
        for i in 0..16 {
            let tmp = data_left ^ feistel_f(data_right, self.subkeys[i]);
            data_left = data_right;
            data_right = tmp;
        }
        let data = ((data_right as u64) << 32) | (data_left as u64);
        let data = permute64(data, &FP);
        BigEndian::write_u64(block, data);
    }
    pub fn decrypt(&self, block: &mut [u8]) {
        let data = BigEndian::read_u64(block);
        let data = permute64(data, &IP);
        let mut data_left : u32 = (data >> 32) as u32;
        let mut data_right : u32 = (data & ((1 << 32) - 1)) as u32;
        for i in 0..16 {
            let tmp = data_left ^ feistel_f(data_right, self.subkeys[15-i]);
            data_left = data_right;
            data_right = tmp;
        }
        let data = ((data_right as u64) << 32) | (data_left as u64);
        let data = permute64(data, &FP);
        BigEndian::write_u64(block, data);
    }
    fn schedule(&mut self, key: u64) {
        let key = permute64(key, &PC1);
        let mut key_left : u32 = (key >> 28) as u32;
        let mut key_right : u32 = (key & ((1 << 28) - 1)) as u32;
        for i in 0..16 {
            key_left =
                ((key_left << NUMROT[i]) & ((1 << 28) - 1)) |
                (key_left >> (28 - NUMROT[i]));
            key_right =
                ((key_right << NUMROT[i]) & ((1 << 28) - 1)) |
                (key_right >> (28 - NUMROT[i]));
            self.subkeys[i] = permute64(
                ((key_left as u64) << 28) | (key_right as u64),
                &PC2);
        }
    }
}

impl TDES {
    pub fn new(key: &[u8]) -> TDES {
        return TDES {
            des1: DES::new(&key[0..8]),
            des2: DES::new(&key[8..16]),
            des3: DES::new(&key[16..24]),
        };
    }
    pub fn encrypt(&self, block: &mut [u8]) {
        self.des1.encrypt(block);
        self.des2.decrypt(block);
        self.des3.encrypt(block);
    }
    pub fn decrypt(&self, block: &mut [u8]) {
        self.des3.decrypt(block);
        self.des2.encrypt(block);
        self.des1.decrypt(block);
    }
}

fn feistel_f(x: u32, subkey: u64) -> u32 {
    let x = x as u64;
    let x =
        ((x >> 31) & 0x000000000001) |
        ((x << 1) & 0x00000000003E) |
        ((x << 3) & 0x000000000FC0) |
        ((x << 5) & 0x00000003F000) |
        ((x << 7) & 0x000000FC0000) |
        ((x << 9) & 0x00003F000000) |
        ((x << 11) & 0x000FC0000000) |
        ((x << 13) & 0x03F000000000) |
        ((x << 15) & 0x7C0000000000) |
        ((x << 47) & 0x800000000000);
    let x = x ^ subkey;
    let x =
        ((S1[(x >> 42) as usize] as u32) << 28) |
        ((S2[((x >> 36) & 63) as usize] as u32) << 24) |
        ((S3[((x >> 30) & 63) as usize] as u32) << 20) |
        ((S4[((x >> 24) & 63) as usize] as u32) << 16) |
        ((S5[((x >> 18) & 63) as usize] as u32) << 12) |
        ((S6[((x >> 12) & 63) as usize] as u32) << 8) |
        ((S7[((x >> 6) & 63) as usize] as u32) << 4) |
        (S8[(x & 63) as usize] as u32);
    let x = permute32(x, &P);
    return x;
}

fn permute32(x: u32, p: &[u32]) -> u32 {
    let mut y = 0;
    for (i, pi) in p.iter().enumerate() {
        y |= ((x >> *pi) & 1) << i;
    }
    return y;
}

fn permute64(x: u64, p: &[u32]) -> u64 {
    let mut y = 0;
    for (i, pi) in p.iter().enumerate() {
        y |= ((x >> *pi) & 1) << i;
    }
    return y;
}

const IP : [u32; 64] = [
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
];

const FP : [u32; 64] = [
    39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24,
];

const P : [u32; 32] = [
    7, 28, 21, 10, 26, 2, 19, 13, 23, 29, 5, 0, 18, 8, 24, 30,
    22, 1, 14, 27, 6, 9, 17, 31, 15, 4, 20, 3, 11, 12, 25, 16,
];

const PC1 : [u32; 56] = [
    60, 52, 44, 36, 59, 51, 43, 35, 27, 19, 11, 3, 58, 50,
    42, 34, 26, 18, 10, 2, 57, 49, 41, 33, 25, 17, 9, 1,
    28, 20, 12, 4, 61, 53, 45, 37, 29, 21, 13, 5, 62, 54,
    46, 38, 30, 22, 14, 6, 63, 55, 47, 39, 31, 23, 15, 7,
];

const PC2 : [u32; 48] = [
    24, 27, 20, 6, 14, 10, 3, 22, 0, 17, 7, 12, 8, 23, 11, 5,
    16, 26, 1, 9, 19, 25, 4, 15, 54, 43, 36, 29, 49, 40, 48, 30,
    52, 44, 37, 33, 46, 35, 50, 41, 28, 53, 51, 55, 32, 45, 39, 42,
];

const S1 : [u8; 64] = [
    14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1,
    3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8,
    4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7,
    15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13
];
const S2 : [u8; 64] = [15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14, 9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5, 0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2, 5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9];
const S3 : [u8; 64] = [10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10, 1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1, 13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7, 11, 4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12];
const S4 : [u8; 64] = [7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3, 1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9, 10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8, 15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14];
const S5 : [u8; 64] = [2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1, 8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6, 4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13, 15, 6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3];
const S6 : [u8; 64] = [12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5, 0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8, 9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10, 7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13];
const S7 : [u8; 64] = [4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10, 3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6, 1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7, 10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12];
const S8 : [u8; 64] = [13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4, 10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2, 7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13, 0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11];

const NUMROT : [u32; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1, ];
