mod cli;

use clap::Clap;
use cli::Opts;
use parser::{header::flags::DnsHeaderFlags, packet::DnsPacket, resources::query::DnsQuery};
use std::{io::Result, net::UdpSocket};

fn forward_query(opts: &Opts, query: &DnsQuery) -> Result<DnsPacket> {
    // 0 as the port means that the OS will pick a port for us
    let socket = UdpSocket::bind(("0.0.0.0", 0))?;

    let mut packet = DnsPacket::new();
    packet.add_query(query.to_owned());

    let bytes = match packet.serialize() {
        Ok(b) => b,
        Err(_e) => todo!(),
    };

    socket.send_to(&bytes[..], (opts.forward_address, opts.forward_port))?;

    let mut buffer = [0; 512];
    let (size, _) = socket.recv_from(&mut buffer)?;

    match DnsPacket::parse(&buffer[..size]) {
        Ok(packet) => Ok(packet),
        Err(_e) => todo!(),
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    let socket = UdpSocket::bind(("0.0.0.0", opts.port))?;
    println!(
        "Server listening on port {} and proxing requests to {}",
        opts.port, opts.forward_address
    );

    loop {
        let mut buffer = [0; 512];

        let (size, src) = socket.recv_from(&mut buffer)?;
        if opts.verbose {
            println!("{} bytes received from {}", size, src);
        }

        let request = match DnsPacket::parse(&buffer[..size]) {
            Ok(packet) => packet,
            Err(e) => {
                println!("Error parsing packet: {:?}", e);
                continue;
            }
        };
        if opts.verbose {
            println!("Received DNS request:\n{:?}", &request);
        }

        let mut response = request.clone();
        response.header.set_flags(DnsHeaderFlags {
            response: true,
            recdesired: true,
            recavail: true,
            ..Default::default()
        });

        for query in request.queries() {
            if let Ok(res) = forward_query(&opts, query) {
                response.add_responses(res.responses().to_owned());
                response.add_records(res.additional_records().to_owned());
                response.add_authorities(res.authorities().to_owned());
            }
        }

        let bytes = match response.serialize() {
            Ok(data) => data,
            Err(e) => {
                println!("Error serializing packet: {}", e);
                continue;
            }
        };

        socket.send_to(&bytes[..], src)?;
        if opts.verbose {
            println!("Sent DNS response:\n{:?}", &response);
        }
    }
}
