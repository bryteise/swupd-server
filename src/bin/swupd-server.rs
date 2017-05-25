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
    Deleted,
}

impl From<i64> for ObjectStatus {
    fn from(v: i64) -> Self {
        match v {
            0 => ObjectStatus::Active,
            1 => ObjectStatus::Experimental,
            2 => ObjectStatus::Deprecated,
            3 => ObjectStatus::Deleted,
            _ => panic!("Invalid value {} to convert a ObjectStatus from", v),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum PathType {
    File,
    Directory,
    SymbolicLink,
}

impl From<i64> for PathType {
    fn from(v: i64) -> Self {
        match v {
            0 => PathType::File,
            1 => PathType::Directory,
            2 => PathType::SymbolicLink,
            _ => panic!("Invalid value {} to convert a PathType from", v),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Package {
    name: String,
    requires: Vec<String>,
    version: String,
    paths: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct Bundle {
    name: String,
    status: ObjectStatus,
    includes: Vec<String>,
    packages: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ChrootConfig {
    packages: Vec<Package>,
    bundles: Vec<Bundle>,
}

#[derive(Debug)]
struct PathObject {
    id: i64,
    path: String,
    path_type: PathType,
    parent: String,
    packages: Option<Vec<i64>>,
    bundles: Option<Vec<i64>>,
    update_version: i64,
    disk_size: Option<i64>,
    download_size: Option<i64>,
    hash: String,
    status: ObjectStatus,
}

#[derive(Debug)]
struct PackageObject {
    id: i64,
    name: String,
    paths: Option<Vec<i64>>,
    requires: Option<Vec<i64>>,
    bundles: Option<Vec<i64>>,
    update_version: i64,
    package_version: String,
    disk_size: Option<i64>,
    download_size: Option<i64>,
    status: ObjectStatus,
}

#[derive(Debug)]
struct BundleObject {
    id: i64,
    name: String,
    packages: Option<Vec<i64>>,
    includes: Option<Vec<i64>>,
    update_version: i64,
    disk_size: Option<i64>,
    download_size: Option<i64>,
    status: ObjectStatus,
}

#[derive(Debug)]
struct Manifest {
    id: i64,
    name: String,
    content_url: String,
    version_url: String,
    format: i64,
    version: i64,
}

#[derive(Debug)]
struct Delta {
    id: i64,
    path_id: i64,
    from_version: i64,
    to_version: i64,
    hash: String,
}

#[derive(Debug)]
struct Rename {
    id: i64,
    from_path: i64,
    to_path: i64,
    from_version: i64,
    to_version: i64,
}

const DB_FORMAT: i64 = 1;

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
                                  .takes_value(true))])
        .get_matches()
}

// Get path_objects from db
fn get_path_objects<'a>(db: &Connection,
                        fields: &'a Vec<&'a str>,
                        content: &'a HashMap<&'a str, &'a str>)
                        -> Result<Vec<PathObject>> {
    let mut checks: Vec<String> = Vec::new();
    for field in fields {
        checks.push(format!("{} in ({})", field, content[field]));
    }
    let query = format!("SELECT id, path, path_type, parent, update_version, \
                         disk_size, download_size, hash, status FROM path_objects WHERE {}",
                        checks.join(" AND "));
    println!("query == {}", query);
    let mut stmt = db.prepare(&query)
        .chain_err(|| format!("Error creation get path_object statement {}", &query))?;
    let mut rows = stmt.query(&[])
        .chain_err(|| format!("Error running get path_object statement {}", &query))?;
    let mut paths: Vec<PathObject> = Vec::new();
    while let Some(rrow) = rows.next() {
        let row = rrow.chain_err(|| "Error reading path_object query row")?;
        let pt: i64 = row.get(2);
        let st: i64 = row.get(8);
        let pth = PathObject {
            id: row.get(0),
            path: row.get(1),
            path_type: PathType::from(pt),
            parent: row.get(3),
            update_version: row.get(4),
            disk_size: row.get(5),
            download_size: row.get(6),
            hash: row.get(7),
            status: ObjectStatus::from(st),
            packages: None,
            bundles: None,
        };
        paths.push(pth);
    }
    Ok(paths)
}

// Get package_objects from db
fn get_package_objects<'a>(db: &Connection,
                           fields: &'a Vec<&'a str>,
                           content: &'a HashMap<&'a str, &'a str>)
                           -> Result<Vec<PackageObject>> {
    let mut checks: Vec<String> = Vec::new();
    for field in fields {
        checks.push(format!("{} in ({})", field, content[field]));
    }
    let query = format!("SELECT id, name, update_version, package_version, disk_size, \
                         download_size, status FROM path_objects WHERE {}",
                        checks.join(" AND "));
    println!("query == {}", query);
    let mut stmt = db.prepare(&query)
        .chain_err(|| format!("Error creation get package_object statement {}", &query))?;
    let mut rows = stmt.query(&[])
        .chain_err(|| format!("Error running get package_object statement {}", &query))?;
    let mut packages: Vec<PackageObject> = Vec::new();
    while let Some(rrow) = rows.next() {
        let row = rrow.chain_err(|| "Error reading package_object query row")?;
        let st: i64 = row.get(6);
        let pkg = PackageObject {
            id: row.get(0),
            name: row.get(1),
            update_version: row.get(2),
            package_version: row.get(3),
            disk_size: row.get(4),
            download_size: row.get(5),
            status: ObjectStatus::from(st),
            paths: None,
            bundles: None,
            requires: None,
        };
        packages.push(pkg);
    }
    Ok(packages)
}

// Get bundle_objects from db
fn get_bundle_objects<'a>(db: &Connection,
                          fields: &'a Vec<&'a str>,
                          content: &'a HashMap<&'a str, &'a str>)
                          -> Result<Vec<BundleObject>> {
    let mut checks: Vec<String> = Vec::new();
    for field in fields {
        checks.push(format!("{} in ({})", field, content[field]));
    }
    let query = format!("SELECT id, name, update_version, \
                         disk_size, download_size, status FROM bundle_objects WHERE {}",
                        checks.join(" AND "));
    println!("query == {}", query);
    let mut stmt = db.prepare(&query)
        .chain_err(|| format!("Error creation get bundle_object statement {}", &query))?;
    let mut rows = stmt.query(&[])
        .chain_err(|| format!("Error running get bundle_object statement {}", &query))?;
    let mut bundles: Vec<BundleObject> = Vec::new();
    while let Some(rrow) = rows.next() {
        let row = rrow.chain_err(|| "Error reading bundle_object query row")?;
        let pt: i64 = row.get(2);
        let st: i64 = row.get(8);
        let bdl = BundleObject {
            id: row.get(0),
            name: row.get(1),
            update_version: row.get(4),
            disk_size: row.get(5),
            download_size: row.get(6),
            status: ObjectStatus::from(st),
            packages: None,
            includes: None,
        };
        bundles.push(bdl);
    }
    Ok(bundles)
}

// Insert initial package and bundle details
fn add_chroot_config_entries(chroot_config: &ChrootConfig,
                             db: &Connection,
                             version: i64)
                             -> Result<()> {
    let mut inserts: Vec<String> = vec![];
    inserts.push("BEGIN;".to_string());
    for package in &chroot_config.packages {
        let line = format!("INSERT INTO package_objects(name, update_version, \
                            package_version, status) VALUES ('{}', {}, '{}', {});",
                           package.name,
                           version,
                           package.version,
                           ObjectStatus::Active as i64);
        inserts.push(line);
    }
    for bundle in &chroot_config.bundles {
        let line = format!("INSERT INTO bundle_objects(name, update_version, status) \
                            VALUES ('{}', {}, {});",
                           bundle.name,
                           version,
                           bundle.status as i64);
        inserts.push(line);
    }
    inserts.push("COMMIT;".to_string());

    db.execute_batch(&inserts.join(""))
        .chain_err(|| "Failed to add packages and bundles to db")?;
    Ok(())
}

// Match paths with the packages they are in
fn add_path_packages(chroot_config: &ChrootConfig, db: &Connection, version: i64) -> Result<()> {
    let vstring = version.to_string();
    let mut stmt_pkg =
        db.prepare("SELECT id FROM package_objects WHERE name = :name AND update_version = \
                      :version")
            .chain_err(|| "Unable to create statement for adding path and package relations")?;

    for package in &chroot_config.packages {
        let mut paths: Vec<&str> = Vec::new();
        for path in &package.paths {
            paths.push(path.to_str().expect("Path not valid unicode"));
        }
        let paths = paths.join("','");
        let mut stmt_inc =
            db.prepare(&format!("SELECT id FROM path_objects WHERE path in ('{}') AND \
                                   update_version = :version",
                                  paths))
                .chain_err(|| "Unable to create statement for adding path and package relations")?;
        let mut pkg_id_rows =
            stmt_pkg.query_map_named(&[(":name", &package.name), (":version", &vstring)],
                                 |row: &rusqlite::Row| -> i64 { row.get(0) })
                .chain_err(|| {
                    format!("Unable to run query to get id for bundle {}", &package.name)
                })?;
        let pkg_id = pkg_id_rows.nth(0)
            .ok_or("Invalid DB")?
            .chain_err(|| {
                format!("Package {} version {} missing after insert",
                        &package.name,
                        &vstring)
            })?;
        let rows = stmt_inc.query_map_named(&[(":version", &vstring)],
                             |row: &rusqlite::Row| -> i64 { row.get(0) })
            .chain_err(|| "Unable to run query to get ids for adding bundle packages")?;

        let mut inserts: Vec<String> = vec!["BEGIN;".to_string()];
        for row in rows {
            let pth_id = row.chain_err(|| {
                    format!("Unable to get a row id from a path required by {}",
                            &package.name)
                })?;
            let line = format!("INSERT INTO path_packages (path_id, package_id) \
                                VALUES ('{}', {});",
                               &pth_id,
                               &pkg_id);
            inserts.push(line);
        }
        inserts.push("COMMIT;".to_string());
        db.execute_batch(&inserts.join(""))
            .chain_err(|| {
                format!("Failed to add path and package relations for {} to db",
                        &package.name)
            })?;
    }
    Ok(())
}

// Update packages with their required packages
fn add_package_requires(chroot_config: &ChrootConfig, db: &Connection, version: i64) -> Result<()> {
    let vstring = version.to_string();
    let mut stmt_pkg =
        db.prepare("SELECT id FROM package_objects WHERE name = :name AND update_version = \
                      :version")
            .chain_err(|| "Unable to create statement for adding package requires")?;

    for package in &chroot_config.packages {
        if package.requires.len() == 0 {
            continue;
        }

        let names = package.requires.join("','");
        let mut stmt_req =
            db.prepare(&format!("SELECT id FROM package_objects WHERE name in ('{}') AND \
                                   update_version = :version",
                                  names))
                .chain_err(|| "Unable to create statement for adding package requires")?;
        let mut pkg_id_rows =
            stmt_pkg.query_map_named(&[(":name", &package.name), (":version", &vstring)],
                                 |row: &rusqlite::Row| -> i64 { row.get(0) })
                .chain_err(|| {
                    format!("Unable to run query to get id for package {}",
                            &package.name)
                })?;
        let pkg_id = pkg_id_rows.nth(0)
            .ok_or("Invalid DB")?
            .chain_err(|| {
                format!("Package {} version {} missing after insert",
                        &package.name,
                        &vstring)
            })?;
        let rows = stmt_req.query_map_named(&[(":version", &vstring)],
                             |row: &rusqlite::Row| -> i64 { row.get(0) })
            .chain_err(|| "Unable to run query to get ids for adding package requires")?;

        let mut inserts: Vec<String> = vec!["BEGIN;".to_string()];
        for row in rows {
            let req_id = row.chain_err(|| {
                    format!("Unable to a get row id from a package required by {}",
                            &package.name)
                })?;
            let line = format!("INSERT INTO package_packages \
                                (package_requires_id, package_required_id) VALUES ('{}', {});",
                               &pkg_id,
                               &req_id);
            inserts.push(line);
        }
        inserts.push("COMMIT;".to_string());
        db.execute_batch(&inserts.join(""))
            .chain_err(|| {
                format!("Failed to add packages requirements for {} to db",
                        &package.name)
            })?;
    }
    Ok(())
}

// Match packages with the bundles they are in
fn add_package_bundles(chroot_config: &ChrootConfig, db: &Connection, version: i64) -> Result<()> {
    let vstring = version.to_string();
    let mut stmt_bdl =
        db.prepare("SELECT id FROM bundle_objects WHERE name = :name AND update_version = \
                      :version")
            .chain_err(|| "Unable to create statement for adding package and bundle relations")?;

    for bundle in &chroot_config.bundles {
        let names = bundle.packages.join("','");
        let mut stmt_inc = db.prepare(&format!("SELECT id FROM package_objects WHERE name in \
                                                ('{}') AND update_version = :version", names))
            .chain_err(|| "Unable to create statement for adding package and bundle relations")?;
        let mut bdl_id_rows = stmt_bdl.query_map_named(&[(":name", &bundle.name),
                                                         (":version", &vstring)],
                                                       |row: &rusqlite::Row| -> i64 { row.get(0) })
            .chain_err(|| format!("Unable to run query to get id for bundle {}", &bundle.name))?;
        let bdl_id = bdl_id_rows.nth(0)
            .ok_or("Invalid DB")?
            .chain_err(|| {
                format!("Bundle {} version {} missing after insert",
                        &bundle.name,
                        &vstring)
            })?;
        let rows = stmt_inc.query_map_named(&[(":version", &vstring)],
                             |row: &rusqlite::Row| -> i64 { row.get(0) })
            .chain_err(|| "Unable to run query to get ids for adding bundle packages")?;

        let mut inserts: Vec<String> = vec!["BEGIN;".to_string()];
        for row in rows {
            let pkg_id = row.chain_err(|| {
                    format!("Unable to get a row id from a package required by {}",
                            &bundle.name)
                })?;
            let line = format!("INSERT INTO package_bundles (package_id, bundle_id) \
                                VALUES ('{}', {});",
                               &pkg_id,
                               &bdl_id);
            inserts.push(line);
        }
        inserts.push("COMMIT;".to_string());
        db.execute_batch(&inserts.join(""))
            .chain_err(|| {
                format!("Failed to add packages and bundle relations for {} to db",
                        &bundle.name)
            })?;
    }
    Ok(())
}

// Update bundles with bundles they include
fn add_bundle_includes(chroot_config: &ChrootConfig, db: &Connection, version: i64) -> Result<()> {
    let vstring = version.to_string();
    let mut stmt_bdl =
        db.prepare("SELECT id FROM bundle_objects WHERE name = :name AND update_version = \
                      :version")
            .chain_err(|| "Unable to create statement for adding bundle includes")?;

    for bundle in &chroot_config.bundles {
        if bundle.includes.len() == 0 {
            continue;
        }

        let names = bundle.includes.join("','");
        let mut stmt_inc =
            db.prepare(&format!("SELECT id FROM bundle_objects WHERE name in ('{}') AND \
                                   update_version = :version",
                                  names))
                .chain_err(|| "Unable to create statement for adding bundle includes")?;
        let mut bdl_id_rows = stmt_bdl.query_map_named(&[(":name", &bundle.name),
                                                         (":version", &vstring)],
                                                       |row: &rusqlite::Row| -> i64 { row.get(0) })
            .chain_err(|| format!("Unable to run query to get id for bundle {}", &bundle.name))?;
        let bdl_id = bdl_id_rows.nth(0)
            .ok_or("Invalid DB")?
            .chain_err(|| {
                format!("Bundle {} version {} missing after insert",
                        &bundle.name,
                        &vstring)
            })?;
        let rows = stmt_inc.query_map_named(&[(":version", &vstring)],
                             |row: &rusqlite::Row| -> i64 { row.get(0) })
            .chain_err(|| "Unable to run query to get ids for adding bundle includes")?;

        let mut inserts: Vec<String> = vec!["BEGIN;".to_string()];
        for row in rows {
            let inc_id = row.chain_err(|| {
                    format!("Unable to a get row id from a bundle included by {}",
                            &bundle.name)
                })?;
            let line = format!("INSERT INTO bundle_bundles \
                                (bundle_includes_id, bundle_included_id) VALUES ('{}', '{}');",
                               &bdl_id,
                               &inc_id);
            inserts.push(line);
        }
        inserts.push("COMMIT;".to_string());
        db.execute_batch(&inserts.join(""))
            .chain_err(|| format!("Failed to add bundle includes for {} to db", &bundle.name))?;
    }
    Ok(())
}

fn update_db_with_config(chroot_config: &ChrootConfig,
                         db: &Connection,
                         version: i64)
                         -> Result<()> {
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
    let target =
        std::fs::read_link(path).chain_err(|| format!("Unable to read symlink {:?}", path))?;
    let mut ctx = digest::Context::new(&digest::SHA256);

    ctx.update(b"L");

    ctx.update(target.to_str()
        .ok_or(format!("Unable to convert symlink {:?} target path {:?} to string",
                       path,
                       target))?
        .as_bytes());

    Ok(ctx.finish())
}

fn get_directory_hash(path: &Path) -> Result<digest::Digest> {
    let metadata = path.metadata()
        .chain_err(|| format!("Unable to get metadata for {:?}", path))?;
    let mut ctx = digest::Context::new(&digest::SHA256);
    let mut mode: Vec<u8> = vec![];

    ctx.update(b"D");

    mode.write_u32::<LittleEndian>(metadata.mode())
        .chain_err(|| format!("Failed to convert mode to bytes for {:?}", path))?;
    ctx.update(&mode);

    Ok(ctx.finish())
}

fn get_file_hash(path: &Path) -> Result<digest::Digest> {
    let mmap = Mmap::open_path(path, Protection::Read)
        .chain_err(|| format!("Unable to open mmap for {:?}", path))?;
    let metadata = path.metadata()
        .chain_err(|| format!("Unable to get metadata for {:?}", path))?;
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

fn add_entry(path: &Path,
             dirent: &DirEntry,
             chroot_config: &ChrootConfig,
             db: &Connection,
             version: i64)
             -> Result<()> {
    let hash = dirent.get_hash()?;
    let meta = dirent.metadata()
        .chain_err(|| format!("Unable to get metadata for {:?}", dirent.path()))?;
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
    db.execute("INSERT INTO path_objects (path, path_type, parent, update_version, disk_size, \
                  hash, status) VALUES (?, ?, ?, ?, ?, ?, ?);",
                 &[&pthstr,
                   &(path_type as i64),
                   &prtstr,
                   &version,
                   &(meta.len() as i64),
                   &format!("{:?}", hash),
                   &(ObjectStatus::Active as i64)])
        .chain_err(|| format!("Unable to insert path {:?} into db", path))?;
    Ok(())
}

fn chroot_to_db(chroot: &Path,
                chroot_config: &ChrootConfig,
                db: &Connection,
                version: i64)
                -> Result<()> {
    let mut path_map: HashMap<&str, usize> = HashMap::new();
    for package in &chroot_config.packages {
        for path in &package.paths {
            path_map.insert(path.to_str()
                                .expect(&format!("Path {:?} in config not unicode", path)),
                            0);
        }
    }

    update_db_with_config(chroot_config, db, version)?;
    for entry in WalkDir::new(chroot) {
        let dirent = entry?;
        let path = Path::new("/").join(dirent.path().strip_prefix(chroot)?);
        let pstr = path.to_str()
            .expect(&format!("Path {:?} in chroot not unicode", path));
        match path_map.get_mut(pstr) {
            Some(count) => *count = 1,
            None => {
                if !dirent.file_type().is_dir() {
                    bail!(format!("Path {:?} found non directory in chroot path \
                                   not in chroot configuration",
                                  pstr));
                }
            }
        }
        add_entry(&path, &dirent, chroot_config, db, version)?;
    }
    for (tmp, count) in &path_map {
        if *count == 0 {
            bail!(format!("Path {} found in chroot configuration but not in path", tmp));
        }
    }
    add_path_packages(chroot_config, db, version)?;
    // let mut map = HashMap::new();
    // map.insert("path", "'/usr/bin', '/usr/lib64', '/usr/bin/bash'");
    // println!("{:?}", get_path_objects(db, &vec!["path"], &map));
    Ok(())
}

fn create_db(db: &Connection) -> Result<()> {
    db.execute_batch("BEGIN; PRAGMA foreign_keys = ON; \
                      \
                      CREATE TABLE manifests ( \
                      version          INTEGER PRIMARY KEY, \
                      name             TEXT NOT NULL, \
                      content_url      TEXT NOT NULL, \
                      version_url      TEXT NOT NULL, \
                      db_format        INTEGER NOT NULL, \
                      format           INTEGER NOT NULL); \
                      \
                      CREATE TABLE path_objects ( \
                      id               INTEGER PRIMARY KEY, \
                      path             TEXT NOT NULL, \
                      path_type        INTEGER NOT NULL, \
                      parent           INTEGER REFERENCES path_objects(id), \
                      update_version   INTEGER NOT NULL, \
                      disk_size        INTEGER, \
                      download_size    INTEGER, \
                      hash             TEXT, \
                      status           INTEGER NOT NULL); \
                      \
                      CREATE TABLE package_objects ( \
                      id               INTEGER PRIMARY KEY, \
                      name             TEXT NOT NULL, \
                      update_version   INTEGER NOT NULL, \
                      package_version  TEXT NOT NULL, \
                      disk_size        INTEGER, \
                      download_size    INTEGER, \
                      status           INTEGER NOT NULL); \
                      \
                      CREATE TABLE bundle_objects ( \
                      id               INTEGER PRIMARY KEY, \
                      name             TEXT NOT NULL, \
                      update_version   INTEGER NOT NULL, \
                      disk_size        INTEGER, \
                      download_size    INTEGER, \
                      status           INTEGER NOT NULL); \
                      \
                      CREATE TABLE deltas ( \
                      id               INTEGER PRIMARY KEY, \
                      path_id          REFERENCES path_objects(id), \
                      from_version     INTEGER NOT NULL, \
                      to_version       INTEGER NOT NULL, \
                      download_size    INTEGER, \
                      hash             TEXT); \
                      \
                      CREATE TABLE renames ( \
                      id               INTEGER PRIMARY KEY, \
                      from_path        REFERENCES path_objects(id), \
                      to_path          REFERENCES path_objects(id), \
                      from_version     INTEGER NOT NULL, \
                      to_version       INTEGER NOT NULL); \
                      \
                      CREATE TABLE path_packages ( \
                      path_id          INTEGER NOT NULL, \
                      package_id       INTEGER NOT NULL, \
                      PRIMARY KEY(path_id, package_id)); \
                      \
                      CREATE TABLE path_bundles ( \
                      path_id          INTEGER NOT NULL, \
                      bundle_id        INTEGER NOT NULL, \
                      PRIMARY KEY(path_id, bundle_id)); \
                      \
                      CREATE TABLE package_packages ( \
                      package_requires_id INTEGER NOT NULL, \
                      package_required_id  INTEGER NOT NULL, \
                      PRIMARY KEY(package_requires_id, package_required_id)); \
                      \
                      CREATE TABLE package_bundles ( \
                      package_id       INTEGER NOT NULL, \
                      bundle_id        INTEGER NOT NULL, \
                      PRIMARY KEY(package_id, bundle_id)); \
                      \
                      CREATE TABLE bundle_bundles ( \
                      bundle_includes_id INTEGER NOT NULL, \
                      bundle_included_id INTEGER NOT NULL, \
                      PRIMARY KEY(bundle_includes_id, bundle_included_id)); \
                      COMMIT;")
        .chain_err(|| "Failed to setup initial database tables")?;
    Ok(())
}

fn make_pre_bump_db(db_path: &Path) -> Result<()> {
    let pre_bump: &Path = &db_path.with_extension("pre-bump");
    fs::rename(db_path, pre_bump).chain_err(|| format!("Failed to move db to pre-bump file at: {:?}", &pre_bump))?;
    Ok(())
}

fn get_db_connection(db_path: &Path,
                     version: i64,
                     previous_version: i64,
                     name: &str,
                     content_url: &str,
                     version_url: &str,
                     format: i64)
                     -> Result<Connection> {
    // Initial version so setup the database
    let conn = if previous_version == 0 {
        if db_path.exists() {
            bail!("Error creating db file, path {:?} already exists", db_path);
        }
        let conn = Connection::open(db_path)
            .chain_err(|| format!("Failed to create new database at: {:?}", db_path))?;
        create_db(&conn)?;
        conn
    } else {
        if !db_path.exists() {
            bail!("Missing db file {:?}", db_path);
        }
        let conn = Connection::open(db_path)
            .chain_err(|| format!("Failed to open existing database at: {:?}", db_path))?;
        let db_format_row = 1;
        let db_format = 2;
        if db_format != DB_FORMAT {
            make_pre_bump_db(db_path)?;
            let new_conn = Connection::open(db_path)
                .chain_err(|| format!("Failed to recreate new database at: {:?}", db_path))?;
            create_db(&new_conn)?;
            new_conn
        } else {
            conn
        }
    };
    Ok(conn)
}

fn load_chroot_config(path: &Path) -> Result<ChrootConfig> {
    let mut buffer = String::new();
    let _ = File::open(path)
        .chain_err(|| format!("Failed to open chroot config file: {:?}", path))?
        .read_to_string(&mut buffer);
    let chroot_config: ChrootConfig =
        serde_json::from_str(&buffer)
            .chain_err(|| format!("Failed to parse chroot config file: {:?}", path))?;
    Ok(chroot_config)
}

fn run_release(matches: &ArgMatches) -> Result<()> {
    // unwrap() used because clap validated these entries exist already
    let chroot = Path::new(matches.value_of("chroot").unwrap());
    let chroot_config_path = Path::new(matches.value_of("chrootconfig").unwrap());
    let chroot_config = load_chroot_config(&chroot_config_path)?;
    let version = matches.value_of("version")
        .unwrap()
        .parse::<i64>()
        .chain_err(|| {
            format!("Unable to parse version from: {}",
                    matches.value_of("version").unwrap())
        })?;
    let previous_version = match matches.value_of("previousversion") {
        None => 0,
        Some(s) => {
            s.parse::<i64>()
                .chain_err(|| format!("Unable to parse previous version from: {}", s))?
        }
    };
    let name = matches.value_of("name").unwrap();
    let content_url = matches.value_of("contenturl").unwrap();
    let version_url = matches.value_of("versionurl").unwrap();
    let format = matches.value_of("format")
        .unwrap()
        .parse::<i64>()
        .chain_err(|| {
            format!("Unable to parse format from: {}",
                    matches.value_of("format").unwrap())
        })?;
    let db_path = Path::new(matches.value_of("database").unwrap());
    let cert_path = Path::new(matches.value_of("certpath").unwrap());

    // TODO validate all args
    // can avoid passing certain arguments if already in db
    let db = get_db_connection(db_path,
                               version,
                               previous_version,
                               name,
                               content_url,
                               version_url,
                               format)?;

    chroot_to_db(chroot, &chroot_config, &db, version)?;

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
