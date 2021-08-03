mod cli;
mod root_servers;
mod traits;

use clap::Clap;
use cli::Opts;
use parser::header::flags::{DnsHeaderFlags, ReplyCode};
use parser::packet::DnsPacket;
use parser::resources::query::DnsQuery;
use parser::resources::record::DnsRecord;
use parser::resources::{DnsClass, DnsRecordType};
use std::io::Result;
use std::net::{IpAddr, UdpSocket};
use traits::RandomElement;

use crate::root_servers::get_root_servers;

fn lookup(query: &DnsQuery, server: (IpAddr, u16)) -> Result<DnsPacket> {
    // 0 as the port means that the OS will pick a port for us
    let socket = UdpSocket::bind(("0.0.0.0", 0))?;

    let mut packet = DnsPacket::new();
    packet.add_query(query.clone());

    let bytes = match packet.serialize() {
        Ok(b) => b,
        Err(_e) => todo!(),
    };

    socket.send_to(&bytes[..], server)?;

    let mut buffer = [0; 512];
    let (size, _) = socket.recv_from(&mut buffer)?;

    match DnsPacket::parse(&buffer[..size]) {
        Ok(packet) => Ok(packet),
        Err(_e) => todo!(),
    }
}

fn recursive_lookup(
    opts: &Opts,
    root_servers: &[DnsRecord],
    query: &DnsQuery,
) -> Result<DnsPacket> {
    let mut server = root_servers.get_random_element().unwrap();

    loop {
        if opts.verbose {
            println!(
                "Trying to resolve {:?} using {:?}",
                query.name,
                server.get_name()
            );
        }

        let response = lookup(query, (server.get_address().unwrap(), 53))?;

        // We found the address we were looking for
        if !response.responses().is_empty() && response.header.flags.rcode == ReplyCode::NoError {
            return Ok(response);
        }

        if let Some(next_server) = response.additional_records().get_random_element() {
            server = next_server;
            continue;
        }

        let unresolved_ns = match response.authorities().get_random_element() {
            Some(ns) => ns,
            None => return Ok(response),
        };

        let recursive_response = recursive_lookup(
            opts,
            root_servers,
            &DnsQuery {
                name: unresolved_ns.get_name().to_owned(),
                class: DnsClass::IN,
                record_type: DnsRecordType::A,
            },
        )?;

        if let Some(next_server) = recursive_response.additional_records().get_random_element() {
            server = next_server;
        } else {
            return Ok(response);
        }
    }
}

fn main() -> Result<()> {
    let root_servers = get_root_servers();
    let opts = Opts::parse();
    let socket = UdpSocket::bind(("0.0.0.0", opts.port))?;
    println!("Server listening on port {}", opts.port);

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
            if let Ok(res) = recursive_lookup(&opts, &root_servers.to_vec(), &query) {
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
