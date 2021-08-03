use clap::{AppSettings, Clap};

#[derive(Clap)]
#[clap(version = "1.0", author = "Jonathan Bouchard <dev.drakota@gmail.com>")]
#[clap(setting = AppSettings::ColoredHelp)]
pub struct Opts {
    #[clap(short, long, default_value = "53")]
    pub port: u16,

    #[clap(short, long)]
    pub verbose: bool,
}
