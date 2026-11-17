use crate::{
    FileInfo, clean_workspace_path, file_info_from_file, open_beneath, workspace_directory,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

pub(super) const MAX_DIRECTORIES: usize = 128;
const MAX_DISCOVERED_ENTRIES: usize = 4096;
const MAX_DEPTH: usize = 16;
const MAX_BATCH: usize = 256;
const MOVE_GRACE: Duration = Duration::from_millis(100);

#[derive(Debug)]
pub(super) enum Failure {
    Io(io::Error),
    Overflow,
    Limit,
    RootChanged,
    InvalidName,
    TopologyChanged,
    Closed,
}

impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl Failure {
    pub(super) fn code(&self) -> &'static str {
        match self {
            Self::Io(error) => crate::file_error_code(error),
            Self::Overflow => "overflow",
            Self::Limit => "operation_limit",
            Self::RootChanged => "directory_changed",
            Self::InvalidName => "invalid_name",
            Self::TopologyChanged => "topology_changed",
            Self::Closed => "closed",
        }
    }
}

#[derive(Serialize)]
pub(super) struct Event {
    pub sequence: u64,
    pub name: String,
    #[serde(rename = "type")]
    pub event_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<FileInfo>,
}

struct Directory {
    file: File,
    relative: String,
    paused: bool,
}

struct Move {
    old: String,
    observed: Instant,
}

pub(super) struct Engine {
    fd: File,
    root: File,
    root_wd: i32,
    workspace_relative: String,
    directories: BTreeMap<i32, Directory>,
    ignored: BTreeSet<i32>,
    moves: BTreeMap<u32, Move>,
    recursive: bool,
    include_entry: bool,
    sequence: u64,
    closed: bool,
}

fn beneath(path: &str, parent: &str) -> bool {
    path == parent
        || path
            .strip_prefix(parent)
            .is_some_and(|rest| rest.starts_with('/'))
}

impl Engine {
    pub(super) fn new(
        workspace: &Path,
        path: &str,
        recursive: bool,
        include_entry: bool,
    ) -> Result<Self, Failure> {
        let relative = clean_workspace_path(path, true)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EACCES))?;
        let root = workspace_directory(workspace, relative)?;
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let mut result = Self {
            fd: unsafe { File::from_raw_fd(fd) },
            root,
            root_wd: -1,
            workspace_relative: relative.into(),
            directories: BTreeMap::new(),
            ignored: BTreeSet::new(),
            moves: BTreeMap::new(),
            recursive,
            include_entry,
            sequence: 0,
            closed: false,
        };
        result.root_wd = result.register("", result.root.try_clone()?)?;
        if recursive {
            result.scan("", &mut 0, 0)?;
        }
        Ok(result)
    }

    pub(super) fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    fn register(&mut self, relative: &str, file: File) -> Result<i32, Failure> {
        for (wd, existing) in &self.directories {
            if existing.relative == relative {
                let old = existing.file.metadata()?;
                let current = file.metadata()?;
                return if old.dev() == current.dev() && old.ino() == current.ino() {
                    Ok(*wd)
                } else {
                    Err(Failure::TopologyChanged)
                };
            }
        }
        if self.directories.len() >= MAX_DIRECTORIES {
            return Err(Failure::Limit);
        }
        let proc_path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
        // Only this held directory fd is followed, never a caller's symlink.
        let mask = libc::IN_ONLYDIR
            | libc::IN_EXCL_UNLINK
            | libc::IN_CREATE
            | libc::IN_MODIFY
            | libc::IN_ATTRIB
            | libc::IN_DELETE
            | libc::IN_MOVED_FROM
            | libc::IN_MOVED_TO
            | libc::IN_DELETE_SELF
            | libc::IN_MOVE_SELF;
        let wd = unsafe { libc::inotify_add_watch(self.raw_fd(), proc_path.as_ptr(), mask) };
        if wd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if let Some(previous) = self.directories.get(&wd) {
            if previous.relative != relative {
                return Err(Failure::TopologyChanged);
            }
        } else {
            self.directories.insert(
                wd,
                Directory {
                    file,
                    relative: relative.into(),
                    paused: false,
                },
            );
        }
        Ok(wd)
    }

    fn open_directory(&self, relative: &str) -> io::Result<File> {
        if relative.is_empty() {
            self.root.try_clone()
        } else {
            open_beneath(
                self.root.as_raw_fd(),
                relative,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                0,
            )
        }
    }

    fn add_tree(&mut self, relative: &str) -> Result<(), Failure> {
        let file = match self.open_directory(relative) {
            Ok(file) => file,
            Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) => {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        self.register(relative, file)?;
        self.scan(relative, &mut 0, relative.split('/').count())
    }

    fn scan(&mut self, relative: &str, count: &mut usize, depth: usize) -> Result<(), Failure> {
        if depth > MAX_DEPTH {
            return Err(Failure::Limit);
        }
        let directory = self.open_directory(relative)?;
        for item in fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
            *count += 1;
            if *count > MAX_DISCOVERED_ENTRIES {
                return Err(Failure::Limit);
            }
            let item = item?;
            if !item.file_type()?.is_dir() {
                continue;
            }
            let name = item
                .file_name()
                .into_string()
                .map_err(|_| Failure::InvalidName)?;
            let child = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            let file = match self.open_directory(&child) {
                Ok(file) => file,
                Err(error)
                    if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            self.register(&child, file)?;
            self.scan(&child, count, depth + 1)?;
        }
        Ok(())
    }

    fn remove_tree(&mut self, prefix: &str, already_ignored: Option<i32>) -> Result<(), Failure> {
        let keys: Vec<_> = self
            .directories
            .iter()
            .filter_map(|(wd, dir)| beneath(&dir.relative, prefix).then_some(*wd))
            .collect();
        for wd in keys {
            self.directories.remove(&wd);
            unsafe { libc::inotify_rm_watch(self.raw_fd(), wd) };
            if already_ignored != Some(wd) {
                self.ignored.insert(wd);
            }
            if self.ignored.len() > MAX_DIRECTORIES * 2 {
                return Err(Failure::Overflow);
            }
        }
        Ok(())
    }

    fn expire_moves(&mut self) -> Result<(), Failure> {
        let expired: Vec<_> = self
            .moves
            .iter()
            .filter_map(|(cookie, movement)| {
                (movement.observed.elapsed() >= MOVE_GRACE).then_some(*cookie)
            })
            .collect();
        for cookie in expired {
            if let Some(movement) = self.moves.remove(&cookie) {
                self.remove_tree(&movement.old, None)?;
            }
        }
        Ok(())
    }

    pub(super) fn drain(&mut self) -> Result<Vec<Event>, Failure> {
        if self.closed {
            return Err(Failure::Closed);
        }
        let result = self.drain_inner();
        if result.is_err() {
            self.closed = true;
        }
        result
    }

    fn drain_inner(&mut self) -> Result<Vec<Event>, Failure> {
        let mut buffer = [0u8; 8192];
        let count = unsafe { libc::read(self.raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                // Drain already queued move-to events before expiring an
                // unmatched move-from, even if this worker was descheduled.
                self.expire_moves()?;
                return Ok(vec![]);
            }
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(vec![]);
            }
            return Err(error.into());
        }
        let mut events = Vec::new();
        let mut offset = 0;
        while offset < count as usize {
            let header_size = std::mem::size_of::<libc::inotify_event>();
            if offset + header_size > count as usize {
                return Err(Failure::Overflow);
            }
            let raw = unsafe {
                buffer
                    .as_ptr()
                    .add(offset)
                    .cast::<libc::inotify_event>()
                    .read_unaligned()
            };
            let end = offset + header_size + raw.len as usize;
            if end > count as usize {
                return Err(Failure::Overflow);
            }
            let bytes = &buffer[offset + header_size..end];
            let name = if bytes.is_empty() {
                ""
            } else {
                let length = bytes
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or(Failure::InvalidName)?;
                std::str::from_utf8(&bytes[..length]).map_err(|_| Failure::InvalidName)?
            };
            self.accept(raw.wd, raw.mask, raw.cookie, name, &mut events)?;
            if events.len() > MAX_BATCH {
                return Err(Failure::Overflow);
            }
            offset = end;
        }
        Ok(events)
    }

    fn accept(
        &mut self,
        wd: i32,
        mask: u32,
        cookie: u32,
        name: &str,
        events: &mut Vec<Event>,
    ) -> Result<(), Failure> {
        if mask & libc::IN_Q_OVERFLOW != 0 {
            return Err(Failure::Overflow);
        }
        if mask & libc::IN_IGNORED != 0 && self.ignored.remove(&wd) {
            return Ok(());
        }
        let Some(directory) = self.directories.get(&wd) else {
            return Ok(());
        };
        if mask & (libc::IN_UNMOUNT | libc::IN_IGNORED | libc::IN_DELETE_SELF) != 0 {
            if wd == self.root_wd {
                return Err(Failure::RootChanged);
            }
            let prefix = directory.relative.clone();
            self.remove_tree(&prefix, (mask & libc::IN_IGNORED != 0).then_some(wd))?;
            return Ok(());
        }
        if mask & libc::IN_MOVE_SELF != 0 {
            return if wd == self.root_wd {
                Err(Failure::RootChanged)
            } else {
                Ok(())
            };
        }
        if name.is_empty() {
            if mask & libc::IN_ATTRIB != 0 {
                self.sequence = self.sequence.checked_add(1).ok_or(Failure::Overflow)?;
                let relative = directory.relative.clone();
                let entry = if self.include_entry {
                    let full = if self.workspace_relative.is_empty() {
                        relative.clone()
                    } else if relative.is_empty() {
                        self.workspace_relative.clone()
                    } else {
                        format!("{}/{relative}", self.workspace_relative)
                    };
                    let path = if full.is_empty() {
                        "/workspace".into()
                    } else {
                        format!("/workspace/{full}")
                    };
                    let basename = full
                        .rsplit('/')
                        .next()
                        .filter(|s| !s.is_empty())
                        .unwrap_or("workspace");
                    file_info_from_file(&directory.file, basename, path).ok()
                } else {
                    None
                };
                events.push(Event {
                    sequence: self.sequence,
                    name: if relative.is_empty() {
                        ".".into()
                    } else {
                        relative
                    },
                    event_type: "chmod",
                    entry,
                });
            }
            return Ok(());
        }
        if name == "."
            || name == ".."
            || name.contains(['/', '\\'])
            || name.chars().any(char::is_control)
        {
            return Err(Failure::InvalidName);
        }
        if directory.paused {
            return Err(Failure::TopologyChanged);
        }
        let relative = if directory.relative.is_empty() {
            name.to_owned()
        } else {
            format!("{}/{name}", directory.relative)
        };
        if relative.len()
            + self.workspace_relative.len()
            + usize::from(!self.workspace_relative.is_empty())
            > 1024
        {
            return Err(Failure::Limit);
        }
        if self.recursive && mask & libc::IN_ISDIR != 0 {
            if mask & libc::IN_MOVED_FROM != 0 {
                if cookie == 0 || self.moves.len() >= MAX_DIRECTORIES {
                    return Err(Failure::TopologyChanged);
                }
                for dir in self.directories.values_mut() {
                    if beneath(&dir.relative, &relative) {
                        dir.paused = true;
                    }
                }
                self.moves.insert(
                    cookie,
                    Move {
                        old: relative.clone(),
                        observed: Instant::now(),
                    },
                );
            } else if mask & libc::IN_MOVED_TO != 0 {
                if let Some(movement) = self.moves.remove(&cookie) {
                    for dir in self.directories.values_mut() {
                        if beneath(&dir.relative, &movement.old) {
                            dir.relative = relative.clone() + &dir.relative[movement.old.len()..];
                            dir.paused = false;
                        }
                    }
                } else {
                    self.add_tree(&relative)?;
                }
            } else if mask & libc::IN_CREATE != 0 {
                self.add_tree(&relative)?;
            }
        }
        for (bit, kind) in [
            (libc::IN_CREATE | libc::IN_MOVED_TO, "create"),
            (libc::IN_MODIFY, "write"),
            (libc::IN_ATTRIB, "chmod"),
            (libc::IN_MOVED_FROM, "rename"),
            (libc::IN_DELETE, "remove"),
        ] {
            if mask & bit == 0 {
                continue;
            }
            self.sequence = self.sequence.checked_add(1).ok_or(Failure::Overflow)?;
            let entry = if self.include_entry && kind != "remove" && kind != "rename" {
                self.entry(wd, name, &relative)
            } else {
                None
            };
            events.push(Event {
                sequence: self.sequence,
                name: relative.clone(),
                event_type: kind,
                entry,
            });
        }
        Ok(())
    }

    fn entry(&self, wd: i32, name: &str, relative: &str) -> Option<FileInfo> {
        let directory = self.directories.get(&wd)?;
        let target = open_beneath(
            directory.file.as_raw_fd(),
            name,
            libc::O_PATH | libc::O_NOFOLLOW,
            0,
        )
        .ok()?;
        let path = if self.workspace_relative.is_empty() {
            format!("/workspace/{relative}")
        } else {
            format!("/workspace/{}/{relative}", self.workspace_relative)
        };
        file_info_from_file(&target, name, path).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Tree(std::path::PathBuf);
    impl Tree {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "osv-inotify-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn drain(engine: &mut Engine) -> Vec<Event> {
        let mut result = vec![];
        loop {
            let batch = engine.drain().unwrap();
            if batch.is_empty() {
                return result;
            }
            result.extend(batch);
        }
    }

    #[test]
    fn transient_files_writes_chmod_rename_and_remove_are_kernel_events() {
        let root = Tree::new();
        let mut engine = Engine::new(&root.0, "/workspace", false, true).unwrap();
        fs::write(root.0.join("short"), b"a").unwrap();
        fs::remove_file(root.0.join("short")).unwrap();
        fs::write(root.0.join("old"), b"payload").unwrap();
        fs::set_permissions(root.0.join("old"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(root.0.join("old"), root.0.join("new")).unwrap();
        let events = drain(&mut engine);
        let pairs: Vec<_> = events
            .iter()
            .map(|e| (e.name.as_str(), e.event_type))
            .collect();
        for wanted in [
            ("short", "create"),
            ("short", "write"),
            ("short", "remove"),
            ("old", "create"),
            ("old", "chmod"),
            ("old", "rename"),
            ("new", "create"),
        ] {
            assert!(pairs.contains(&wanted), "{pairs:?}");
        }
        assert!(
            events
                .windows(2)
                .all(|p| p[1].sequence == p[0].sequence + 1)
        );
        let info = events
            .iter()
            .find(|e| e.name == "new" && e.event_type == "create")
            .unwrap()
            .entry
            .as_ref()
            .unwrap();
        assert_eq!(info.path, "/workspace/new");
        assert_eq!(info.size, 7);
    }

    #[test]
    fn recursive_directories_follow_internal_moves_and_exclude_outside_tree() {
        let root = Tree::new();
        fs::create_dir_all(root.0.join("watch/old/sub")).unwrap();
        let mut engine = Engine::new(&root.0, "/workspace/watch", true, false).unwrap();
        fs::rename(root.0.join("watch/old"), root.0.join("watch/new")).unwrap();
        let events = drain(&mut engine);
        assert!(
            events
                .iter()
                .any(|e| e.name == "old" && e.event_type == "rename")
        );
        fs::write(root.0.join("watch/new/sub/file"), b"x").unwrap();
        assert!(
            drain(&mut engine)
                .iter()
                .any(|e| e.name == "new/sub/file" && e.event_type == "write")
        );
        fs::rename(root.0.join("watch/new"), root.0.join("outside")).unwrap();
        drain(&mut engine);
        std::thread::sleep(MOVE_GRACE + Duration::from_millis(5));
        drain(&mut engine);
        fs::write(root.0.join("outside/sub/hidden"), b"x").unwrap();
        assert!(drain(&mut engine).is_empty());
        assert_eq!(engine.directories.len(), 1);
    }

    #[test]
    fn new_and_moved_in_subtrees_are_registered_without_following_links() {
        let root = Tree::new();
        let outside = Tree::new();
        fs::create_dir(root.0.join("watch")).unwrap();
        fs::create_dir_all(root.0.join("incoming/sub")).unwrap();
        symlink(&outside.0, root.0.join("watch/link")).unwrap();
        let mut engine = Engine::new(&root.0, "/workspace/watch", true, true).unwrap();
        fs::create_dir(root.0.join("watch/made")).unwrap();
        drain(&mut engine);
        fs::write(root.0.join("watch/made/file"), b"a").unwrap();
        assert!(drain(&mut engine).iter().any(|e| e.name == "made/file"));
        fs::rename(root.0.join("incoming"), root.0.join("watch/incoming")).unwrap();
        drain(&mut engine);
        fs::write(root.0.join("watch/incoming/sub/file"), b"b").unwrap();
        assert!(
            drain(&mut engine)
                .iter()
                .any(|e| e.name == "incoming/sub/file")
        );
        fs::write(outside.0.join("hidden"), b"keep").unwrap();
        assert!(drain(&mut engine).is_empty());
        assert!(Engine::new(&root.0, "/workspace/watch/link", false, false).is_err());
        assert!(Engine::new(&root.0, "/workspace/../input", false, false).is_err());
    }

    #[test]
    fn deleted_or_moved_watch_root_stops_and_descriptor_count_is_bounded() {
        let root = Tree::new();
        fs::create_dir(root.0.join("watch")).unwrap();
        let mut engine = Engine::new(&root.0, "/workspace/watch", false, false).unwrap();
        fs::rename(root.0.join("watch"), root.0.join("moved")).unwrap();
        assert!(matches!(engine.drain(), Err(Failure::RootChanged)));
        assert!(matches!(engine.drain(), Err(Failure::Closed)));
        for n in 0..MAX_DIRECTORIES {
            fs::create_dir(root.0.join(format!("moved/{n}"))).unwrap();
        }
        assert!(matches!(
            Engine::new(&root.0, "/workspace/moved", true, false),
            Err(Failure::Limit)
        ));
    }

    #[test]
    fn overflow_and_ambiguous_move_are_explicit_errors() {
        let root = Tree::new();
        let mut engine = Engine::new(&root.0, "/workspace", false, false).unwrap();
        assert!(matches!(
            engine.accept(-1, libc::IN_Q_OVERFLOW, 0, "", &mut vec![]),
            Err(Failure::Overflow)
        ));
        engine.directories.get_mut(&engine.root_wd).unwrap().paused = true;
        assert!(matches!(
            engine.accept(engine.root_wd, libc::IN_CREATE, 0, "name", &mut vec![]),
            Err(Failure::TopologyChanged)
        ));
        assert_eq!(Failure::Overflow.code(), "overflow");
    }

    #[test]
    fn root_permission_change_has_a_relative_self_name_and_root_metadata() {
        let root = Tree::new();
        let mut engine = Engine::new(&root.0, "/workspace", false, true).unwrap();
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
        let events = drain(&mut engine);
        let changed = events
            .iter()
            .find(|e| e.name == "." && e.event_type == "chmod")
            .unwrap();
        assert_eq!(changed.entry.as_ref().unwrap().path, "/workspace");
        assert_eq!(changed.entry.as_ref().unwrap().file_type, "directory");
    }

    #[test]
    fn unexpected_kernel_removal_does_not_retain_an_ignored_descriptor_forever() {
        let root = Tree::new();
        let mut engine = Engine::new(&root.0, "/workspace", true, false).unwrap();
        for number in 0..256 {
            let name = format!("child-{number}");
            fs::create_dir(root.0.join(&name)).unwrap();
            drain(&mut engine);
            let wd = *engine
                .directories
                .iter()
                .find(|(_, d)| d.relative == name)
                .unwrap()
                .0;
            assert_eq!(unsafe { libc::inotify_rm_watch(engine.raw_fd(), wd) }, 0);
            drain(&mut engine);
            assert!(engine.ignored.is_empty());
            assert_eq!(engine.directories.len(), 1);
            fs::remove_dir(root.0.join(&name)).unwrap();
            drain(&mut engine);
        }
    }
}
