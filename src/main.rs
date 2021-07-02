mod objects;

use objects::packet::*;

use std::fs;

fn main() {
    let input = fs::read("./examples/query.txt").expect("Error while trying to read the file");
    let packet = DnsPacket::parse(&input[..]);
    dbg!(packet);
}
