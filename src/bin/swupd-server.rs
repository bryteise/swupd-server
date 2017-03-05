#![recursion_limit = "1024"]
#[macro_use]
extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
extern crate rusqlite;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate walkdir;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use errors::*;
use rusqlite::Connection;
use std::fs;
use std::fs::{File, FileType};
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

mod errors {
    // Create the Error, ErrorKind, ResultExt, and Result types
    error_chain!{
        foreign_links {
            Io(::std::io::Error) #[doc = "Error with file I/O"];
            Json(::serde_json::Error) #[doc = "Error decoding json"];
            ParseInt(::std::num::ParseIntError) #[doc = "Error parsing an integer"];
            Sql(::rusqlite::Error) #[doc = "Error with SQLite interaction"];
            WalkDirPath(::walkdir::Error) #[doc = "Error reading path"];
        }
    }
}

#[derive(Debug, Deserialize)]
enum ObjectStatus {
    Active,
    Experimental,
    Deprecated,
    Deleted
}

#[derive(Debug, Deserialize)]
struct Package {
    name: String,
    requires: Vec<String>,
    version: String,
    status: ObjectStatus,
    paths: Vec<PathBuf>
}

#[derive(Debug, Deserialize)]
struct Bundle {
    name: String,
    status: ObjectStatus,
    includes: Vec<String>,
    packages: Vec<String>
}

#[derive(Debug, Deserialize)]
struct ChrootConfig {
    packages: Vec<Package>,
    bundles: Option<Vec<Bundle>>
}

#[derive(Debug)]
struct PathObject {
    id: i64,
    path: PathBuf,
    path_type: FileType,
    parent: PathBuf,
    packages: Option<Vec<i64>>,
    bundles: Option<Vec<i64>>,
    update_version: u32,
    disk_size: u32,
    download_size: u32,
    hash: String,
    status: ObjectStatus
}

#[derive(Debug)]
struct PackageObject {
    id: i64,
    name: String,
    paths: Vec<i64>,
    requires: Option<Vec<i64>>,
    bundles: Option<Vec<i64>>,
    update_version: u32,
    package_version: String,
    disk_size: u32,
    download_size: u32,
    hash: String,
    status: ObjectStatus
}

#[derive(Debug)]
struct BundleObject {
    id: i64,
    name: String,
    packages: Vec<i64>,
    includes: Option<Vec<i64>>,
    paths: Vec<i64>,
    update_version: u32,
    disk_size: u32,
    download_size: u32,
    hash: String,
    status: ObjectStatus
}

#[derive(Debug)]
struct Manifest {
    id: i64,
    name: String,
    content_url: String,
    version_url: String,
    format: u32,
    version: u32
}

#[derive(Debug)]
struct Delta {
    id: i64,
    from_version: u32,
    to_version: u32,
    from_type: FileType,
    to_type: FileType,
    from_object: i64,
    to_object: i64
}

#[derive(Debug)]
struct Rename {
    id: i64,
    from_path: i64,
    to_path: i64,
    from_version: u32,
    to_version: u32,
}

fn get_matches<'a>(app: &'a App) -> ArgMatches<'a> {
    app.clone()
        .setting(AppSettings::SubcommandRequired)
        .version(crate_version!())
        .author(crate_authors!())
        .about("swupd-server")
        .subcommands(vec![SubCommand::with_name("release")
                          .about("make release")
                          .arg(Arg::with_name("chroot")
                               .short("c")
                               .long("chroot")
                               .help("path to os content chroot")
                               .required(true)
                               .takes_value(true))
                          .arg(Arg::with_name("chrootconfig")
                               .short("m")
                               .long("chrootconfig")
                               .help("path to os content chroot config file")
                               .required(true)
                               .takes_value(true))
                          .arg(Arg::with_name("version")
                               .short("v")
                               .long("version")
                               .help("release version to create")
                               .required(true)
                               .takes_value(true))
                          .arg(Arg::with_name("previousversion")
                               .short("p")
                               .long("previousversion")
                               .help("previous version to update")
                               .required(false)
                               .takes_value(true))
                          .arg(Arg::with_name("name")
                               .short("n")
                               .long("name")
                               .help("os name")
                               .required(true)
                               .takes_value(true))
                          .arg(Arg::with_name("contenturl")
                               .short("C")
                               .long("contenturl")
                               .help("os content url")
                               .required(true)
                               .takes_value(true))
                          .arg(Arg::with_name("versionurl")
                               .short("V")
                               .long("versionurl")
                               .help("os version url")
                               .required(true)
                               .takes_value(true))
                          .arg(Arg::with_name("format")
                               .short("f")
                               .long("format")
                               .help("os format version")
                               .required(true)
                               .takes_value(true))
                          .arg(Arg::with_name("database")
                               .short("d")
                               .long("database")
                               .help("path to database file")
                               .required(true)
                               .takes_value(true))
                          .arg(Arg::with_name("certpath")
                               .short("t")
                               .long("certpath")
                               .help("path to certificate file")
                               .required(true)
                               .takes_value(true))]
        )
        .get_matches()
}

fn add_entry(dirent: &DirEntry, chroot_config: &ChrootConfig) -> Result<()> {
//    print!("{:?}", dirent.metadata());
    bail!("not yet!");
    Ok(())
}

fn scan_chroot(chroot: &Path, chroot_config: &ChrootConfig, version: u32) -> Result<()> {
    for entry in WalkDir::new(chroot) {
        let dirent = entry?;
        add_entry(&dirent, chroot_config)?;
        //println!("{}", dirent.path().display());
    }
    Ok(())
}

fn get_db_connection(db_path: &Path, version: u32, previous_version: u32, name: &str, content_url: &str, version_url: &str, format: u32) -> Result<Connection> {
    let conn = if previous_version == 0 {
        if db_path.exists() {
            bail!("Error creating db file, path {:?} already exists", db_path);
        }
        let conn = Connection::open(db_path)?;
        conn.execute_batch("BEGIN;
                            CREATE TABLE manifests (
                             id               INTEGER PRIMARY KEY,
                             name             TEXT NOT NULL,
                             content_url      TEXT NOT NULL,
                             version_url      TEXT NOT NULL,
                             format           INTEGER NOT NULL,
                             version          INTEGER NOT NULL,
                            );
                            CREATE TABLE path_objects (
                             id               INTEGER PRIMARY KEY,
                             path             TEXT NOT NULL,
                             path_type        INTEGER NOT NULL,
                             parent           TEXT,
                             packages         BLOB,
                             bundles          BLOB,
                             update_version   INTEGER NOT NULL,
                             disk_size        INTEGER NOT NULL,
                             download_size    INTEGER NOT NULL,
                             hash             INTEGER NOT NULL,
                             status           INTEGER NOT NULL,
                            );
                            CREATE TABLE package_objects (
                             id               INTEGER PRIMARY KEY,
                             name             TEXT NOT NULL,
                             paths            BLOB,
                             requires         BLOB,
                             bundles          BLOB,
                             update_version   INTEGER NOT NULL,
                             package_version  TEXT NOT NULL,
                             disk_size        INTEGER NOT NULL,
                             download_size    INTEGER NOT NULL,
                             hash             INTEGER NOT NULL,
                             status           INTEGER NOT NULL,
                            );
                            CREATE TABLE bundle_objects (
                             id               INTEGER PRIMARY KEY,
                             name             TEXT NOT NULL,
                             packages         BLOB,
                             includes         BLOB,
                             paths            BLOB,
                             update_version   INTEGER NOT NULL,
                             disk_size        INTEGER NOT NULL,
                             download_size    INTEGER NOT NULL,
                             hash             INTEGER NOT NULL,
                             status           INTEGER NOT NULL,
                            );
                            CREATE TABLE deltas (
                             id               INTEGER PRIMARY KEY,
                             from_version     INTEGER NOT NULL,
                             to_version       INTEGER NOT NULL,
                             from_type        INTEGER NOT NULL,
                             to_type          INTEGER NOT NULL,
                             from_object      INTEGER NOT NULL,
                             to_object        INTEGER NOT NULL,
                            );
                            CREATE TABLE renames (
                             id               INTEGER PRIMARY KEY,
                             from_path        INTEGER NOT NULL,
                             to_path          INTEGER NOT NULL,
                             from_version     INTEGER NOT NULL,
                             to_version       INTEGER NOT NULL,
                             from_object      INTEGER NOT NULL,
                             to_object        INTEGER NOT NULL,
                            );

")?;
        conn
    } else {
        if ! db_path.exists() {
            bail!("Missing db file {:?}", db_path);
        }
        Connection::open(db_path)?
    };
    Ok(conn)
}

fn load_chroot_config(path: &Path) -> Result<ChrootConfig> {
    let mut buffer = String::new();
    let _ = File::open(path)?.read_to_string(&mut buffer);
    let chroot_config: ChrootConfig = serde_json::from_str(&buffer)?;
    Ok(chroot_config)
}

fn run_release(matches: &ArgMatches) -> Result<()> {
    let chroot = Path::new(matches.value_of("chroot").unwrap());
    let chroot_config_path = Path::new(matches.value_of("chrootconfig").unwrap());
    let chroot_config = load_chroot_config(&chroot_config_path)?;
    let version = matches.value_of("version").unwrap().parse::<u32>()?;
    let previous_version = match matches.value_of("previousversion") {
        // TODO: add better validation
        None => 0,
        Some(s) => s.parse::<u32>()?,
    };
    let name = matches.value_of("name").unwrap();
    let content_url = matches.value_of("contenturl").unwrap();
    let version_url = matches.value_of("versionurl").unwrap();
    let format = matches.value_of("format").unwrap().parse::<u32>()?;
    let db_path = Path::new(matches.value_of("database").unwrap());
    let cert_path = Path::new(matches.value_of("certpath").unwrap());

    // TODO validate all args
    // can avoid passing certain arguments if already in db
    let db = get_db_connection(db_path, version, previous_version, name, content_url, version_url, format)?;

    scan_chroot(chroot, &chroot_config, version)?;

    Ok(())
}

fn process_command(matches: ArgMatches) -> Result<()> {
    let cmd_result = match matches.subcommand() {
        ("release", Some(sub_m)) => run_release(sub_m),
        _ => {
            bail!("Error processing subcommands (shouldn't be able to get here)");
        }
    };

    cmd_result
}

fn main() {
    env_logger::init().unwrap();
    let app = App::new("clr");
    let matches = get_matches(&app);
    if let Err(ref e) = process_command(matches) {
        error!("{}", e);

        for e in e.iter().skip(1) {
            error!("caused by: {}", e);
        }

        if let Some(backtrace) = e.backtrace() {
            error!("Backtrace: {:?}", backtrace);
        }

        ::std::process::exit(1);
    }

}
