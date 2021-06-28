mod objects;

use objects::packet::*;

use std::{error::Error, fs};

fn main() -> Result<(), Box<dyn Error>> {
    let input = fs::read("./examples/query.txt")?;
    let packet = DnsPacket::parse(&input[..]).unwrap().1;
    dbg!(packet);

    Ok(())
}
