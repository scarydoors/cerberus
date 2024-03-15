use rand::rngs::OsRng;
use std::io::Read;
use std::{path::Path, io::Write};
use std::fs::File;
use cerberus_core::primitive::NonceCounter;

fn main() {
    let mut counter = NonceCounter::default();
    println!("{:?}", counter.as_bytes());
    counter.advance();
    println!("{:?}", counter.as_bytes());
}
