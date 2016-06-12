// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

pub mod md5;
pub mod sha1;
pub mod sha2;
pub mod sha3;
pub mod arcfour;
pub mod des;

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
}
