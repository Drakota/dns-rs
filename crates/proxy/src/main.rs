mod cli;

use clap::Clap;
use cli::Opts;
use parser::{
    header::{flags::DnsHeaderFlags, DnsHeader},
    packet::DnsPacket,
    resources::query::DnsQuery,
};
use std::{error::Error, net::UdpSocket};

fn forward_query(opts: &Opts, query: &DnsQuery) -> Result<DnsPacket, Box<dyn Error>> {
    // 0 as the port means that the OS will pick a port for us
    let socket = UdpSocket::bind(("0.0.0.0", 0))?;

    let packet = DnsPacket {
        header: DnsHeader {
            transaction_id: 6666,
            flags: DnsHeaderFlags {
                ..Default::default()
            },
            queries: 1,
            responses: 0,
            add_rr: 0,
            auth_rr: 0,
        },
        queries: vec![query.clone()],
        responses: vec![],
        additional_records: vec![],
        authorities: vec![],
    };

    socket.send_to(
        &(packet.serialize()?)[..],
        (opts.proxy_address, opts.proxy_port),
    )?;

    let mut buffer = [0; 512];
    let (size, _) = socket.recv_from(&mut buffer)?;

    let res = DnsPacket::parse(&buffer[..size])?;
    Ok(res)
}

fn handle_request(opts: &Opts, socket: &UdpSocket) -> Result<(), Box<dyn Error>> {
    let mut buffer = [0; 512];

    let (size, src) = socket.recv_from(&mut buffer)?;
    if opts.verbose {
        println!("{} bytes received from {}", size, src);
    }

    let request = DnsPacket::parse(&buffer[..size])?;
    if opts.verbose {
        println!("Received DNS request:\n{:?}", &request);
    }

    let mut response = request;
    response.header.flags.response = true;
    response.header.flags.recdesired = true;
    response.header.flags.recavail = true;

    for query in &response.queries {
        if let Ok(res) = forward_query(opts, query) {
            response.responses.extend(res.responses.iter().cloned());
            response
                .additional_records
                .extend(res.additional_records.iter().cloned());
            response.authorities.extend(res.authorities.iter().cloned());
            response.header.responses += res.responses.len() as u16;
        }
    }

    socket.send_to(&(response.serialize()?)[..], src)?;
    if opts.verbose {
        println!("Sent DNS response:\n{:?}", &response);
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let opts = Opts::parse();
    let socket = UdpSocket::bind(("0.0.0.0", opts.port))?;

    loop {
        if let Err(e) = handle_request(&opts, &socket) {
            println!("Error while handling DNS request: {:?}", e)
        }
    }
}
