// Copyright (c) 2016 Masaki Hara
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

extern crate crypt_impl;

use std::env;
use std::io::{self, Write};
use crypt_impl::arcfour::ArcfourReader;

fn main() {
    let mut key : Vec<u8> = "foo".as_bytes().to_vec();
    let args : Vec<String> = env::args().collect();
    if args.len() > 1 {
        key = args[1].as_bytes().to_vec();
    }
    let stdin = io::stdin();
    let stdin = stdin.lock();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let mut stdin_arcfour = ArcfourReader::new(stdin, &key);
    match io::copy(&mut stdin_arcfour, &mut stdout) {
        Ok(_) => {}
        Err(e) => {
            writeln!(&mut io::stderr(), "Error: {}", e).unwrap();
        }
    }
}
