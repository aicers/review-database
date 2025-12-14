use std::{env, path::PathBuf, process::exit};

use anyhow::{Context, Result};
use config::File;
use review_database::migrate_data_dir;
use serde::Deserialize;

#[cfg(feature = "migrate")]
fn main() -> Result<()> {
    let config = Config::load_config(parse().as_deref())?;

    println!("Starting migration process...");
    println!("Migrating data directory...");
    // Note: Passing None for the ip2location::DB means country codes will be set to None
    // during migration. To resolve country codes from IP addresses, load an ip2location
    // database and pass Some(&db) instead.
    migrate_data_dir(&config.data_dir, &config.backup_dir, None).context("migration failed")?;
    Ok(())
}

fn parse() -> Option<String> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() <= 1 {
        return None;
    }

    if args[1] == "--help" || args[1] == "-h" {
        println!("{} {}", bin(), version());
        println!();
        println!(
            "USAGE: \
            \n    {} [CONFIG] \
            \n \
            \nFLAGS: \
            \n    -h, --help       Prints help information \
            \n    -V, --version    Prints version information \
            \n \
            \nARG: \
            \n    <CONFIG>    A TOML config file",
            bin()
        );
        exit(0);
    }
    if args[1] == "--version" || args[1] == "-V" {
        println!("{}", version());
        exit(0);
    }

    Some(args[1].clone())
}

fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn bin() -> &'static str {
    env!("CARGO_BIN_NAME")
}

pub struct Config {
    data_dir: PathBuf,
    backup_dir: PathBuf,
}

impl Config {
    /// Reads configuration from the file on disk and environment variables and
    /// returns Config struct.
    ///
    /// # Errors
    ///
    /// If input arguments are invalid, an error will be returned.
    pub fn load_config(path: Option<&str>) -> Result<Self> {
        let builder = config::Config::builder()
            .set_default("data_dir", env::current_dir()?.join("data").to_str())
            .context("cannot set the default data directory")?
            .set_default("backup_dir", env::current_dir()?.join("backup").to_str())
            .context("cannot set the default backup directory")?;
        let config: ConfigParser = if let Some(path) = path {
            builder.add_source(File::with_name(path))
        } else {
            builder
        }
        .build()
        .context("cannot build the config")?
        .try_deserialize()?;
        Ok(Self {
            data_dir: config.data_dir,
            backup_dir: config.backup_dir,
        })
    }
}

#[derive(Debug, Deserialize)]
struct ConfigParser {
    data_dir: PathBuf,
    backup_dir: PathBuf,
}
