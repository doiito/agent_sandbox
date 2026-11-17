use super::{DATA_BYTES, MAX_BYTES, MAX_ENTRIES, MAX_PATH_BYTES, Result, valid_member};
use serde::Serialize;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Fingerprint {
    dev: u64,
    ino: u64,
    mode: u32,
    size: u64,
    links: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
impl Fingerprint {
    fn new(meta: Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            mode: meta.mode(),
            size: meta.size(),
            links: meta.nlink(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            ctime: (meta.ctime(), meta.ctime_nsec()),
        }
    }
    fn file_type(&self) -> Result<&'static str> {
        match self.mode & libc::S_IFMT {
            libc::S_IFDIR => Ok("directory"),
            libc::S_IFREG if self.links == 1 => Ok("file"),
            _ => Err("denied"),
        }
    }
    fn read(file: &File) -> Result<Self> {
        file.metadata()
            .map(Self::new)
            .map_err(|error| crate::file_error_code(&error))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct Entry {
    pub path: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub size: u64,
    pub mode: u32,
    #[serde(skip)]
    fingerprint: Fingerprint,
}

#[derive(Debug, PartialEq, Eq)]
struct State {
    selected: Fingerprint,
    entries: BTreeMap<String, Entry>,
    path_bytes: usize,
    payload_bytes: u64,
}

fn open(root: &File, path: &str, flags: i32) -> Result<File> {
    // openat2 validates O_PATH flags strictly; O_NONBLOCK is only valid on
    // the subsequent readable descriptor, never on the inspection handle.
    let nonblock = if flags & libc::O_PATH == 0 {
        libc::O_NONBLOCK
    } else {
        0
    };
    crate::open_beneath(
        root.as_raw_fd(),
        path,
        flags | libc::O_NOFOLLOW | nonblock,
        0,
    )
    .map_err(|error| crate::file_error_code(&error))
}

impl State {
    fn insert(&mut self, path: String, fingerprint: Fingerprint) -> Result<()> {
        if !valid_member(&path) {
            return Err("invalid_path");
        }
        if fingerprint.dev != self.selected.dev {
            return Err("denied");
        }
        let kind = fingerprint.file_type()?;
        let size = if kind == "file" { fingerprint.size } else { 0 };
        if self.entries.len() >= MAX_ENTRIES
            || path.len() > MAX_PATH_BYTES - self.path_bytes
            || size > MAX_BYTES - self.payload_bytes
        {
            return Err("too_large");
        }
        self.path_bytes += path.len();
        self.payload_bytes += size;
        let entry = Entry {
            path: path.clone(),
            kind,
            size,
            mode: fingerprint.mode,
            fingerprint,
        };
        if self.entries.insert(path, entry).is_some() {
            return Err("conflict");
        }
        Ok(())
    }

    fn walk(
        &mut self,
        selected: &File,
        path: &str,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        check()?;
        let directory = open(
            selected,
            if path.is_empty() { "." } else { path },
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        let before = Fingerprint::read(&directory)?;
        let duplicate = directory.try_clone().map_err(|_| "io_error")?;
        use std::os::fd::IntoRawFd;
        let raw = duplicate.into_raw_fd();
        let stream = unsafe { libc::fdopendir(raw) };
        if stream.is_null() {
            unsafe {
                libc::close(raw);
            }
            return Err("io_error");
        }
        let stream = crate::DirectoryStream(stream);
        loop {
            check()?;
            unsafe {
                *libc::__errno_location() = 0;
            }
            let item = unsafe { libc::readdir(stream.0) };
            if item.is_null() {
                if std::io::Error::last_os_error().raw_os_error() != Some(0) {
                    return Err("io_error");
                }
                break;
            }
            let name = unsafe { CStr::from_ptr((*item).d_name.as_ptr()) }
                .to_str()
                .map_err(|_| "invalid_path")?;
            if name == "." || name == ".." {
                continue;
            }
            let member = if path.is_empty() {
                name.to_owned()
            } else {
                format!("{path}/{name}")
            };
            if !valid_member(&member) {
                return Err("invalid_path");
            }
            let child = open(selected, &member, libc::O_PATH)?;
            let fingerprint = Fingerprint::read(&child)?;
            let directory = fingerprint.file_type()? == "directory";
            self.insert(member.clone(), fingerprint)?;
            if directory {
                self.walk(selected, &member, check)?;
            }
        }
        if before != Fingerprint::read(&directory)? {
            return Err("conflict");
        }
        Ok(())
    }

    fn capture(
        root: &File,
        relative: &str,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        check()?;
        let selected = open(root, relative, libc::O_PATH)?;
        let fingerprint = Fingerprint::read(&selected)?;
        if fingerprint.dev != Fingerprint::read(root)?.dev {
            return Err("denied");
        }
        let kind = fingerprint.file_type()?;
        let mut state = Self {
            selected: fingerprint.clone(),
            entries: BTreeMap::new(),
            path_bytes: 0,
            payload_bytes: 0,
        };
        if kind == "directory" {
            state.walk(&selected, "", check)?;
        } else {
            state.insert(
                relative
                    .rsplit('/')
                    .next()
                    .ok_or("invalid_path")?
                    .to_owned(),
                fingerprint,
            )?;
        }
        if state.selected != Fingerprint::read(&selected)? {
            return Err("conflict");
        }
        Ok(state)
    }
}

pub(super) struct Snapshot {
    root: File,
    relative: String,
    state: State,
}

impl Snapshot {
    pub fn capture(
        workspace: &Path,
        path: &str,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        let relative = crate::clean_workspace_path(path, true).ok_or("invalid_path")?;
        let relative = if relative.is_empty() { "." } else { relative };
        let root = File::open(workspace).map_err(|error| crate::file_error_code(&error))?;
        let state = State::capture(&root, relative, check)?;
        Ok(Self {
            root,
            relative: relative.into(),
            state,
        })
    }
    pub fn kind(&self) -> &'static str {
        // capture has already rejected all other types.
        if self.state.selected.mode & libc::S_IFMT == libc::S_IFDIR {
            "directory"
        } else {
            "file"
        }
    }
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.state.entries.values()
    }
    pub fn payload_bytes(&self) -> u64 {
        self.state.payload_bytes
    }
    pub fn files(&self) -> usize {
        self.entries().filter(|entry| entry.kind == "file").count()
    }
    pub fn count(&self) -> usize {
        self.state.entries.len()
    }

    pub fn read_file(
        &self,
        entry: &Entry,
        check: &mut impl FnMut() -> Result<()>,
        mut emit: impl FnMut(u64, &[u8]) -> Result<()>,
    ) -> Result<()> {
        check()?;
        let path = if self.kind() == "file" {
            self.relative.clone()
        } else {
            format!("{}/{}", self.relative, entry.path)
        };
        // Inspect without opening devices/FIFOs, then open only the regular
        // file. The fingerprint is rechecked after the second open and read.
        let probe = open(&self.root, &path, libc::O_PATH)?;
        if entry.fingerprint != Fingerprint::read(&probe)? {
            return Err("conflict");
        }
        // Reopen the already inspected regular inode, rather than resolving
        // the workspace name again across a possible rename-to-device race.
        let mut file =
            File::open(format!("/proc/self/fd/{}", probe.as_raw_fd())).map_err(|_| "io_error")?;
        if entry.fingerprint != Fingerprint::read(&file)? {
            return Err("conflict");
        }
        let mut data = [0u8; DATA_BYTES];
        let mut offset = 0u64;
        while offset < entry.size {
            check()?;
            let count = (entry.size - offset).min(DATA_BYTES as u64) as usize;
            file.read_exact(&mut data[..count])
                .map_err(|_| "conflict")?;
            emit(offset, &data[..count])?;
            offset += count as u64;
        }
        check()?;
        if file.read(&mut data[..1]).map_err(|_| "io_error")? != 0
            || entry.fingerprint != Fingerprint::read(&file)?
        {
            return Err("conflict");
        }
        Ok(())
    }

    pub fn verify(&self, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
        check()?;
        let result = State::capture(&self.root, &self.relative, check);
        check()?;
        if result.as_ref().is_ok_and(|state| *state == self.state) {
            Ok(())
        } else {
            Err("conflict")
        }
    }
}
