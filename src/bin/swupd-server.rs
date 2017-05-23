#![recursion_limit = "1024"]
//TODO turn off
#![allow(dead_code)]
#![allow(unreachable_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

extern crate byteorder;
#[macro_use]
extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate error_chain;
extern crate futures;
extern crate futures_cpupool;
#[macro_use]
extern crate log;
extern crate memmap;
extern crate nix;
extern crate rayon;
extern crate ring;
extern crate rusqlite;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate walkdir;

use byteorder::{LittleEndian, WriteBytesExt};
use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use errors::*;
use futures::Future;
use futures_cpupool::{CpuFuture, CpuPool};
use memmap::{Mmap, Protection};
use rayon::prelude::*;
use ring::digest;
use rusqlite::Connection;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs;
use std::fs::{File, FileType};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
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
            StripPrefix(::std::path::StripPrefixError) #[doc = "Error removing path prefix"];
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
enum ObjectStatus {
    Active,
    Experimental,
    Deprecated,
    Deleted
}

#[derive(Clone, Copy, Debug)]
enum PathType {
    File,
    Directory,
    SymbolicLink
}

#[derive(Debug, Deserialize)]
struct Package {
    name: String,
    requires: Vec<String>,
    version: String,
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
    bundles: Vec<Bundle>
}

#[derive(Debug)]
struct PathObject {
    id: u32,
    path: String,
    path_type: PathType,
    parent: Option<String>,
    packages: Option<Vec<u32>>,
    bundles: Option<Vec<u32>>,
    update_version: u32,
    disk_size: Option<u32>,
    download_size: Option<u32>,
    hash: String,
    status: ObjectStatus
}

#[derive(Debug)]
struct PackageObject {
    id: u32,
    name: String,
    paths: Vec<u32>,
    requires: Option<Vec<u32>>,
    bundles: Option<Vec<u32>>,
    update_version: u32,
    package_version: String,
    disk_size: Option<u32>,
    download_size: Option<u32>,
    status: ObjectStatus
}

#[derive(Debug)]
struct BundleObject {
    id: u32,
    name: String,
    packages: Vec<u32>,
    includes: Option<Vec<u32>>,
    paths: Vec<u32>,
    update_version: u32,
    disk_size: Option<u32>,
    download_size: Option<u32>,
    status: ObjectStatus
}

#[derive(Debug)]
struct Manifest {
    id: u32,
    name: String,
    content_url: String,
    version_url: String,
    format: u32,
    version: u32
}

#[derive(Debug)]
struct Delta {
    id: u32,
    path_id: u32,
    from_version: u32,
    to_version: u32,
    hash: String
}

#[derive(Debug)]
struct Rename {
    id: u32,
    from_path: u32,
    to_path: u32,
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

// // Get path_objects from db
// fn get_path_objects(fields: &Vec<&str>, content: &HashMap<&str, &str>) -> Result<Vec<PathObject>> {
//     let mut checks: Vec<String> = Vec::new();
//     for field in fields {
//         checks.push(format!("{} in ({})", field, query[field]));
//     }
//     let query = format!("SELECT (id, path, path_type, parent, update_version, disk_size, download_size, hash, status) FROM path_objects WHERE {}", checks.join(" AND "));
//     let mut stmt = db.prepare(&query).chain_err(|| format!("Error creation get path_object statement {}", &query))?;
//     let mut rows = stmt.query(&[]).chain_err(|| format!("Error running get path_object statement {}", &query))?;
//     let paths: Vec<PathObject> = Vec::new();
//     while let Some(rrow) = rows.next() {
//         let row = rrow.chain_err(|| "Error reading package_object query row");
//         let pkg = PackageObject {
//             id = row.get(0),
//             path = row.get(1),
//             path_type = row.get(2) as PathType,
//             parent = Path::new(row.get(3)),
//             update_version = row.get(4),
            
//         };
//     }
// }

// Insert initial package and bundle details
fn add_chroot_config_entries(chroot_config: &ChrootConfig, db: &Connection, version: u32) -> Result<()> {
    let mut inserts: Vec<String> = vec![];
    inserts.push("BEGIN;".to_string());
    for package in &chroot_config.packages {
        let line = format!("INSERT INTO package_objects(name, update_version, package_version, status) VALUES ('{}', {}, '{}', {});",
                           package.name,
                           version,
                           package.version,
                           ObjectStatus::Active as u32);
        inserts.push(line);
    }
    for bundle in &chroot_config.bundles {
        let line = format!("INSERT INTO bundle_objects(name, update_version, status) VALUES ('{}', {}, {});",
                           bundle.name,
                           version,
                           bundle.status as u32);
        inserts.push(line);
    }
    inserts.push("COMMIT;".to_string());

    db.execute_batch(&inserts.join("")).chain_err(|| "Failed to add packages and bundles to db")?;
    Ok(())
}

// Update packages with their required packages
fn add_package_requires(chroot_config: &ChrootConfig, db: &Connection, version: u32) -> Result<()> {
    let vstring = version.to_string();
    let mut stmt_pkg = db.prepare("SELECT id FROM package_objects WHERE name = :name AND update_version = :version").chain_err(|| "Unable to create statement for adding package requires")?;

    for package in &chroot_config.packages {
        if package.requires.len() == 0 {
            continue;
        }

        let names = package.requires.join("','");
        let mut stmt_req = db.prepare(&format!("SELECT id FROM package_objects WHERE name in ('{}') AND update_version = :version", names)).chain_err(|| "Unable to create statement for adding package requires")?;
        let mut pkg_id_rows = stmt_pkg.query_map_named(&[(":name", &package.name), (":version", &vstring)], |row: &rusqlite::Row| -> u32 { row.get(0)} )
            .chain_err(|| format!("Unable to run query to get id for package {}", &package.name))?;
        let pkg_id = pkg_id_rows.nth(0).ok_or("Invalid DB")?.chain_err(|| format!("Package {} version {} missing after insert", &package.name, &vstring))?;
        let rows = stmt_req.query_map_named(&[(":version", &vstring)], |row: &rusqlite::Row| -> u32 { row.get(0)} )
            .chain_err(|| "Unable to run query to get ids for adding package requires")?;

        let mut inserts: Vec<String> = vec!["BEGIN;".to_string()];
        for row in rows {
            let req_id = row.chain_err(|| format!("Unable to a get row id from a package required by {}", &package.name))?;
            let line = format!("INSERT INTO package_packages (package_requires_id, package_required_id) VALUES ('{}', {});",
                               &pkg_id, &req_id);
            inserts.push(line);
        }
        inserts.push("COMMIT;".to_string());
        db.execute_batch(&inserts.join("")).chain_err(|| format!("Failed to add packages requirements for {} to db", &package.name))?;
    }
    Ok(())
}

// Match packages with the bundles they are in
fn add_package_bundles(chroot_config: &ChrootConfig, db: &Connection, version: u32) -> Result<()> {
    let vstring = version.to_string();
    let mut stmt_bdl = db.prepare("SELECT id FROM bundle_objects WHERE name = :name AND update_version = :version").chain_err(|| "Unable to create statement for adding package and bundle relations")?;

    for bundle in &chroot_config.bundles {
        let names = bundle.packages.join("','");
        let mut stmt_inc = db.prepare(&format!("SELECT id FROM package_objects WHERE name in ('{}') AND update_version = :version", names)).chain_err(|| "Unable to create statement for adding package and bundle relations")?;
        let mut bdl_id_rows = stmt_bdl.query_map_named(&[(":name", &bundle.name), (":version", &vstring)], |row: &rusqlite::Row| -> u32 { row.get(0)} )
            .chain_err(|| format!("Unable to run query to get id for bundle {}", &bundle.name))?;
        let bdl_id = bdl_id_rows.nth(0).ok_or("Invalid DB")?.chain_err(|| format!("Bundle {} version {} missing after insert", &bundle.name, &vstring))?;
        let rows = stmt_inc.query_map_named(&[(":version", &vstring)], |row: &rusqlite::Row| -> u32 { row.get(0)} )
            .chain_err(|| "Unable to run query to get ids for adding bundle packages")?;

        let mut inserts: Vec<String> = vec!["BEGIN;".to_string()];
        for row in rows {
            let pkg_id = row.chain_err(|| format!("Unable to get a row id from a package required by {}", &bundle.name))?;
            let line = format!("INSERT INTO package_bundles (package_id, bundle_id) VALUES ('{}', {});",
                               &pkg_id, &bdl_id);
            inserts.push(line);
        }
        inserts.push("COMMIT;".to_string());
        db.execute_batch(&inserts.join("")).chain_err(|| format!("Failed to add packages and bundle relations for {} to db", &bundle.name))?;
    }
    Ok(())
}

// Update bundles with bundles they include
fn add_bundle_includes(chroot_config: &ChrootConfig, db: &Connection, version: u32) -> Result<()> {
    let vstring = version.to_string();
    let mut stmt_bdl = db.prepare("SELECT id FROM bundle_objects WHERE name = :name AND update_version = :version").chain_err(|| "Unable to create statement for adding bundle includes")?;

    for bundle in &chroot_config.bundles {
        if bundle.includes.len() == 0 {
            continue;
        }

        let names = bundle.includes.join("','");
        let mut stmt_inc = db.prepare(&format!("SELECT id FROM bundle_objects WHERE name in ('{}') AND update_version = :version", names)).chain_err(|| "Unable to create statement for adding bundle includes")?;
        let mut bdl_id_rows = stmt_bdl.query_map_named(&[(":name", &bundle.name), (":version", &vstring)], |row: &rusqlite::Row| -> u32 { row.get(0)} )
            .chain_err(|| format!("Unable to run query to get id for bundle {}", &bundle.name))?;
        let bdl_id = bdl_id_rows.nth(0).ok_or("Invalid DB")?.chain_err(|| format!("Bundle {} version {} missing after insert", &bundle.name, &vstring))?;
        let rows = stmt_inc.query_map_named(&[(":version", &vstring)], |row: &rusqlite::Row| -> u32 { row.get(0)} )
            .chain_err(|| "Unable to run query to get ids for adding bundle includes")?;

        let mut inserts: Vec<String> = vec!["BEGIN;".to_string()];
        for row in rows {
            let inc_id = row.chain_err(|| format!("Unable to a get row id from a bundle included by {}", &bundle.name))?;
            let line = format!("INSERT INTO bundle_bundles (bundle_includes_id, bundle_included_id) VALUES ('{}', '{}');",
                               &bdl_id, &inc_id);
            inserts.push(line);
        }
        inserts.push("COMMIT;".to_string());
        db.execute_batch(&inserts.join("")).chain_err(|| format!("Failed to add bundle includes for {} to db", &bundle.name))?;
    }
    Ok(())
}

fn update_db_with_config(chroot_config: &ChrootConfig, db: &Connection, version: u32) -> Result<()> {
    add_chroot_config_entries(chroot_config, db, version)?;
    add_package_requires(chroot_config, db, version)?;
    add_package_bundles(chroot_config, db, version)?;
    add_bundle_includes(chroot_config, db, version)?;
    Ok(())
}

trait Hashable {
    fn get_hash(&self) -> Result<digest::Digest>;
}

impl Hashable for DirEntry {
    fn get_hash(&self) -> Result<digest::Digest> {
        if self.file_type().is_symlink() {
            get_symbolic_link_hash(self.path())
        } else if self.file_type().is_dir() {
            get_directory_hash(self.path())
        } else if self.file_type().is_file() {
            get_file_hash(self.path())
        } else {
            bail!("Invalid filetype entry: {:?}", self.path());
        }
    }
}

fn get_symbolic_link_hash(path: &Path) -> Result<digest::Digest> {
    let target = std::fs::read_link(path).chain_err(|| format!("Unable to read symlink {:?}", path))?;
    let mut ctx = digest::Context::new(&digest::SHA256);

    ctx.update(b"L");

    ctx.update(target.to_str()
               .ok_or(format!("Unable to convert symlink {:?} target path {:?} to string", path, target))?
               .as_bytes());

    Ok(ctx.finish())
}

fn get_directory_hash(path: &Path) -> Result<digest::Digest> {
    let metadata = path.metadata().chain_err(|| format!("Unable to get metadata for {:?}", path))?;
    let mut ctx = digest::Context::new(&digest::SHA256);
    let mut mode: Vec<u8> = vec![];

    ctx.update(b"D");

    mode.write_u32::<LittleEndian>(metadata.mode())
        .chain_err(|| format!("Failed to convert mode to bytes for {:?}", path))?;
    ctx.update(&mode);

    Ok(ctx.finish())
}

fn get_file_hash(path: &Path) -> Result<digest::Digest> {
    let mmap = Mmap::open_path(path, Protection::Read).chain_err(|| format!("Unable to open mmap for {:?}", path))?;
    let metadata = path.metadata().chain_err(|| format!("Unable to get metadata for {:?}", path))?;
    let mut ctx = digest::Context::new(&digest::SHA256);
    let mut mode: Vec<u8> = vec![];

    ctx.update(b"F");

    mode.write_u32::<LittleEndian>(metadata.mode())
        .chain_err(|| format!("Failed to convert mode to bytes for {:?}", path))?;
    ctx.update(&mode);

    let bytes: &[u8] = unsafe { mmap.as_slice() };
    ctx.update(&bytes);

    Ok(ctx.finish())
}

fn add_entry(path: &Path, dirent: &DirEntry, chroot_config: &ChrootConfig, db: &Connection, version: u32) -> Result<()> {
    let hash = dirent.get_hash()?;
    let path_type = if dirent.file_type().is_symlink() {
        PathType::SymbolicLink
    } else if dirent.file_type().is_dir() {
        PathType::Directory
    } else if dirent.file_type().is_file() {
        PathType::File
    } else {
        bail!("Invalid filetype entry: {:?}", dirent.path());
    };
    let parent = path.parent().unwrap_or(Path::new("/"));
    let pthstr = path.to_str().expect("Path not valid unicode");
    let prtstr = parent.to_str().expect("Path not valid unicode");
    db.execute("INSERT INTO path_objects (path, path_type, parent, update_version, hash, status) VALUES (?, ?, ?, ?, ?, ?);",
               &[&pthstr,
                 &(path_type as u32),
                 &prtstr,
                 &version,
                 &hash.as_ref(),
                 &(ObjectStatus::Active as u32)])
        .chain_err(|| format!("Unable to insert path {:?} into db", path))?;
    Ok(())
}

fn scan_chroot(chroot: &Path, chroot_config: &ChrootConfig, db: &Connection, version: u32) -> Result<()> {
    let mut path_map: HashMap<&str, usize> = HashMap::new();
    for package in &chroot_config.packages {
        for path in &package.paths {
            path_map.insert(path.to_str().expect(&format!("Path {:?} in config not unicode", path)), 0);
        }
    }

    update_db_with_config(chroot_config, db, version)?;
    for entry in WalkDir::new(chroot) {
        let dirent = entry?;
        let path = Path::new("/").join(dirent.path().strip_prefix(chroot)?);
        let pstr = path.to_str().expect(&format!("Path {:?} in chroot not unicode", path));
        match path_map.get_mut(pstr) {
            Some(count) => *count = 1,
            None => {
                if !dirent.file_type().is_dir() {
                    bail!(format!("Path {:?} found non directory in chroot path not in chroot configuration", pstr));
                }
            }
        }
        add_entry(&path, &dirent, chroot_config, db, version)?;
    };
    for (tmp, count) in &path_map {
        if *count == 0 {
            bail!(format!("Path {} found in chroot configuration but not in path", tmp));
        }
    }
    bail!("not yet");
    Ok(())
}

fn get_db_connection(db_path: &Path, version: u32, previous_version: u32, name: &str, content_url: &str, version_url: &str, format: u32) -> Result<Connection> {
    // Initial version so setup the database
    let conn = if previous_version == 0 {
        if db_path.exists() {
            bail!("Error creating db file, path {:?} already exists", db_path);
        }
        let conn = Connection::open(db_path).chain_err(|| format!("Failed to create new database at: {:?}", db_path))?;
        conn.execute_batch("BEGIN;
                            PRAGMA foreign_keys = ON;
                            CREATE TABLE manifests (
                             version          INTEGER PRIMARY KEY,
                             name             TEXT NOT NULL,
                             content_url      TEXT NOT NULL,
                             version_url      TEXT NOT NULL,
                             format           INTEGER NOT NULL
                            );
                            CREATE TABLE path_objects (
                             id               INTEGER PRIMARY KEY,
                             path             TEXT NOT NULL,
                             path_type        INTEGER NOT NULL,
                             parent           INTEGER REFERENCES path_objects(id),
                             update_version   INTEGER NOT NULL,
                             disk_size        INTEGER,
                             download_size    INTEGER,
                             hash             TEXT,
                             status           INTEGER NOT NULL
                            );
                            CREATE TABLE package_objects (
                             id               INTEGER PRIMARY KEY,
                             name             TEXT NOT NULL,
                             update_version   INTEGER NOT NULL,
                             package_version  TEXT NOT NULL,
                             disk_size        INTEGER,
                             download_size    INTEGER,
                             status           INTEGER NOT NULL
                            );
                            CREATE TABLE bundle_objects (
                             id               INTEGER PRIMARY KEY,
                             name             TEXT NOT NULL,
                             update_version   INTEGER NOT NULL,
                             disk_size        INTEGER,
                             download_size    INTEGER,
                             status           INTEGER NOT NULL
                            );
                            CREATE TABLE deltas (
                             id               INTEGER PRIMARY KEY,
                             path_id          REFERENCES path_objects(id),
                             from_version     INTEGER NOT NULL,
                             to_version       INTEGER NOT NULL,
                             download_size    INTEGER,
                             hash             TEXT
                            );
                            CREATE TABLE renames (
                             id               INTEGER PRIMARY KEY,
                             from_path        REFERENCES path_objects(id),
                             to_path          REFERENCES path_objects(id),
                             from_version     INTEGER NOT NULL,
                             to_version       INTEGER NOT NULL
                            );
                            CREATE TABLE path_packages (
                             path_id          INTEGER NOT NULL,
                             package_id       INTEGER NOT NULL,
                             PRIMARY KEY(path_id, package_id)
                            );
                            CREATE TABLE path_bundles (
                             path_id          INTEGER NOT NULL,
                             bundle_id        INTEGER NOT NULL,
                             PRIMARY KEY(path_id, bundle_id)
                            );
                            CREATE TABLE package_packages (
                             package_requires_id INTEGER NOT NULL,
                             package_required_id  INTEGER NOT NULL,
                             PRIMARY KEY(package_requires_id, package_required_id)
                            );
                            CREATE TABLE package_bundles (
                             package_id       INTEGER NOT NULL,
                             bundle_id        INTEGER NOT NULL,
                             PRIMARY KEY(package_id, bundle_id)
                            );
                            CREATE TABLE bundle_bundles (
                             bundle_includes_id INTEGER NOT NULL,
                             bundle_included_id INTEGER NOT NULL,
                             PRIMARY KEY(bundle_includes_id, bundle_included_id)
                            );
                            COMMIT;
").chain_err(|| "Failed to setup initial database tables")?;
        conn
    } else {
        if ! db_path.exists() {
            bail!("Missing db file {:?}", db_path);
        }
        Connection::open(db_path).chain_err(|| format!("Failed to open existing database at: {:?}", db_path))?
    };
    Ok(conn)
}

fn load_chroot_config(path: &Path) -> Result<ChrootConfig> {
    let mut buffer = String::new();
    let _ = File::open(path).chain_err(|| format!("Failed to open chroot config file: {:?}", path))?.read_to_string(&mut buffer);
    let chroot_config: ChrootConfig = serde_json::from_str(&buffer).chain_err(|| format!("Failed to parse chroot config file: {:?}", path))?;
    Ok(chroot_config)
}

fn run_release(matches: &ArgMatches) -> Result<()> {
    let chroot = Path::new(matches.value_of("chroot").unwrap());
    let chroot_config_path = Path::new(matches.value_of("chrootconfig").unwrap());
    let chroot_config = load_chroot_config(&chroot_config_path)?;
    let version = matches.value_of("version").unwrap().parse::<u32>().chain_err(|| format!("Unable to parse version from: {}", matches.value_of("version").unwrap()))?;
    let previous_version = match matches.value_of("previousversion") {
        // TODO: add better validation
        None => 0,
        Some(s) => s.parse::<u32>().chain_err(|| format!("Unable to parse previous version from: {}", s))?,
    };
    let name = matches.value_of("name").unwrap();
    let content_url = matches.value_of("contenturl").unwrap();
    let version_url = matches.value_of("versionurl").unwrap();
    let format = matches.value_of("format").unwrap().parse::<u32>().chain_err(|| format!("Unable to parse format from: {}", matches.value_of("format").unwrap()))?;
    let db_path = Path::new(matches.value_of("database").unwrap());
    let cert_path = Path::new(matches.value_of("certpath").unwrap());

    // TODO validate all args
    // can avoid passing certain arguments if already in db
    let db = get_db_connection(db_path, version, previous_version, name, content_url, version_url, format)?;

    scan_chroot(chroot, &chroot_config, &db, version)?;

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
    if nix::unistd::getuid() != 0 {
        error!("swupd-server must be run as root");
        ::std::process::exit(-1);
    }
    let app = App::new("clr");
    let matches = get_matches(&app);
    if let Err(ref e) = process_command(matches) {
        error!("{}", e);

        for e in e.iter().skip(1) {
            error!("Caused by error: {}", e);
        }

        if let Some(backtrace) = e.backtrace() {
            error!("Backtrace: {:?}", backtrace);
        }

        ::std::process::exit(-1);
    }
}
