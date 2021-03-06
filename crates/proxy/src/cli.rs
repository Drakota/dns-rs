use clap::{AppSettings, Clap};
use std::net::IpAddr;

#[derive(Clap)]
#[clap(version = "1.0", author = "Jonathan Bouchard <dev.drakota@gmail.com>")]
#[clap(setting = AppSettings::ColoredHelp)]
pub struct Opts {
    #[clap(long("f"))]
    pub forward_address: IpAddr,

    #[clap(long("fp"), default_value = "53")]
    pub forward_port: u16,

    #[clap(short, long, default_value = "53")]
    pub port: u16,

    #[clap(short, long)]
    pub verbose: bool,
}
