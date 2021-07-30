use clap::{AppSettings, Clap};
use std::net::IpAddr;

#[derive(Clap)]
#[clap(version = "1.0", author = "Jonathan Bouchard <dev.drakota@gmail.com>")]
#[clap(setting = AppSettings::ColoredHelp)]
pub struct Opts {
    #[clap(long("pa"))]
    pub proxy_address: IpAddr,

    #[clap(long("pp"), default_value = "53")]
    pub proxy_port: u16,

    #[clap(short, long, default_value = "53")]
    pub port: u16,

    #[clap(short, long)]
    pub verbose: bool,
}
