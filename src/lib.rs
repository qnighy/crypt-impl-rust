// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

extern crate byteorder;
extern crate time;
extern crate rand;
extern crate num;

mod misc;
pub mod md5;
pub mod sha1;
pub mod sha2;
pub mod sha3;
pub mod arcfour;
pub mod des;
pub mod aes;
pub mod tls;

#[cfg(test)]
mod tests {
    #[test]
    fn test_arcfour() {
        use arcfour::Arcfour;
        use std::io::Read;
        let mut r = Arcfour::new("foo".as_bytes());
        let mut buf = [0; 16];
        match r.read(&mut buf) {
            Ok(n) => {
                assert!(n == buf.len());
                assert!(buf == [
                    0xab, 0x22, 0xed, 0x29, 0xc8, 0x61, 0x5b, 0x32,
                    0x36, 0x8a, 0xb5, 0xf5, 0x9d, 0xae, 0x53, 0x8b
                ]);
            },
            Err(_) => assert!(false)
        }
    }

    #[test]
    fn test_des() {
        use des::DES;
        let des = DES::new(&[0x10, 0x31, 0x6E, 0x02, 0x8C, 0x8F, 0x3B, 0x4A]);
        let mut text = [0, 0, 0, 0, 0, 0, 0, 0];
        des.encrypt(&mut text);
        assert!(text == [0x82, 0xDC, 0xBA, 0xFB, 0xDE, 0xAB, 0x66, 0x02]);
        des.decrypt(&mut text);
        assert!(text == [0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_aes_encrypt_128() {
        use aes::AES;
        let aes = AES::new(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ]);
        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ];
        aes.encrypt(&mut block);
        assert_eq!(block, [
            0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30,
            0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A,
        ]);
        aes.decrypt(&mut block);
        assert_eq!(block, [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ]);
    }
}
