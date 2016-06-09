// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

pub mod md5;
pub mod sha1;
pub mod sha2;
pub mod arcfour;

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
}
