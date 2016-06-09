// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

extern crate crypt_impl;

use std::io::{self, Write};
use crypt_impl::md5::MD5Writer;

fn main() {
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let mut md5w = MD5Writer::new();
    match io::copy(&mut stdin, &mut md5w) {
        Ok(_) => {
            let sum = md5w.sum();
            for b in sum.iter() {
                print!("{:02x}", b);
            }
            println!("");
        }
        Err(e) => {
            writeln!(&mut io::stderr(), "Error: {}", e).unwrap();
        }
    }
}
