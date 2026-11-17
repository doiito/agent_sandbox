use super::{
    DirectoryStream, FileInfo, OpenHow, RESOLVE_BENEATH, RESOLVE_NO_SYMLINKS, RESOLVE_NO_XDEV,
};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;

pub(super) fn rename(workspace: &Path, source: &str, destination: &str) -> io::Result<FileInfo> {
    let (old_parent, old_name) = source.rsplit_once('/').unwrap_or(("", source));
    let (new_parent, new_name) = destination.rsplit_once('/').unwrap_or(("", destination));
    let old_parent = super::workspace_directory(workspace, old_parent)?;
    let new_parent = super::workspace_directory(workspace, new_parent)?;
    let old_name =
        CString::new(old_name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let new_name_c =
        CString::new(new_name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if unsafe {
        libc::renameat(
            old_parent.as_raw_fd(),
            old_name.as_ptr(),
            new_parent.as_raw_fd(),
            new_name_c.as_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    old_parent.sync_all()?;
    new_parent.sync_all()?;
    let target = super::open_beneath(
        new_parent.as_raw_fd(),
        new_name,
        libc::O_PATH | libc::O_NOFOLLOW,
        0,
    )?;
    super::file_info_from_file(&target, new_name, format!("/workspace/{destination}"))
}

fn open_name(parent: RawFd, name: &CStr, flags: i32) -> io::Result<File> {
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            parent,
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

fn remove_at(parent: RawFd, name: &CStr, remaining: &mut usize, depth: usize) -> io::Result<()> {
    if *remaining == 0 {
        return Err(io::Error::from_raw_os_error(libc::E2BIG));
    }
    *remaining -= 1;
    let target = open_name(parent, name, libc::O_PATH | libc::O_NOFOLLOW)?;
    let directory = target.metadata()?.is_dir();
    if directory {
        if depth > 32 {
            return Err(io::Error::from_raw_os_error(libc::E2BIG));
        }
        let file = open_name(
            parent,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )?;
        let fd = unsafe { libc::dup(file.as_raw_fd()) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let raw = unsafe { libc::fdopendir(fd) };
        if raw.is_null() {
            let error = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(error);
        }
        let stream = DirectoryStream(raw);
        loop {
            unsafe { *libc::__errno_location() = 0 };
            let item = unsafe { libc::readdir(stream.0) };
            if item.is_null() {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(0) {
                    break;
                }
                return Err(error);
            }
            let bytes = unsafe { CStr::from_ptr((*item).d_name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            if bytes.is_empty() || bytes.contains(&b'/') {
                return Err(io::Error::from_raw_os_error(libc::EACCES));
            }
            let child =
                CString::new(bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            remove_at(file.as_raw_fd(), &child, remaining, depth + 1)?;
        }
        file.sync_all()?;
    }
    if unsafe {
        libc::unlinkat(
            parent,
            name.as_ptr(),
            if directory { libc::AT_REMOVEDIR } else { 0 },
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn remove(workspace: &Path, relative: &str) -> io::Result<()> {
    let (parent, name) = relative.rsplit_once('/').unwrap_or(("", relative));
    let parent = super::workspace_directory(workspace, parent)?;
    let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    remove_at(parent.as_raw_fd(), &name, &mut 4096, 1)?;
    parent.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Tree(PathBuf);
    impl Tree {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "osv-tree-{}-{}",
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

    #[test]
    fn moves_files_directories_and_overwrites_with_destination_info() {
        let root = Tree::new();
        fs::create_dir_all(root.0.join("old/sub")).unwrap();
        fs::write(root.0.join("old/sub/input"), b"payload").unwrap();
        let info = rename(&root.0, "old", "new").unwrap();
        assert_eq!(info.path, "/workspace/new");
        assert_eq!(info.file_type, "directory");
        assert!(!root.0.join("old").exists());
        fs::write(root.0.join("output"), b"replace").unwrap();
        let info = rename(&root.0, "new/sub/input", "output").unwrap();
        assert_eq!(info.size, 7);
        assert_eq!(fs::read(root.0.join("output")).unwrap(), b"payload");
        assert!(rename(&root.0, "new", "new/sub/invalid").is_err());
        assert!(root.0.join("new/sub").is_dir());
    }

    #[test]
    fn recursive_remove_unlinks_links_without_following_them() {
        let root = Tree::new();
        let outside = Tree::new();
        fs::write(outside.0.join("sentinel"), b"keep").unwrap();
        fs::create_dir_all(root.0.join("tree/a/b")).unwrap();
        fs::write(root.0.join("tree/a/b/file"), b"data").unwrap();
        symlink(&outside.0, root.0.join("tree/external")).unwrap();
        symlink("absent", root.0.join("tree/dangling")).unwrap();
        remove(&root.0, "tree").unwrap();
        assert!(!root.0.join("tree").exists());
        assert_eq!(fs::read(outside.0.join("sentinel")).unwrap(), b"keep");
        assert_eq!(
            remove(&root.0, "tree").unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
    }

    #[test]
    fn parents_cannot_follow_links() {
        let root = Tree::new();
        let outside = Tree::new();
        fs::write(outside.0.join("sentinel"), b"keep").unwrap();
        symlink(&outside.0, root.0.join("link")).unwrap();
        assert!(rename(&root.0, "link/sentinel", "new").is_err());
        assert!(remove(&root.0, "link/sentinel").is_err());
        rename(&root.0, "link", "renamed-link").unwrap();
        remove(&root.0, "renamed-link").unwrap();
        assert_eq!(fs::read(outside.0.join("sentinel")).unwrap(), b"keep");
    }

    #[test]
    fn partial_delete_budget_is_reported_and_retriable() {
        let root = Tree::new();
        fs::create_dir(root.0.join("tree")).unwrap();
        for n in 0..5 {
            fs::write(root.0.join(format!("tree/{n}")), b"x").unwrap();
        }
        let parent = File::open(&root.0).unwrap();
        let name = CString::new("tree").unwrap();
        assert_eq!(
            remove_at(parent.as_raw_fd(), &name, &mut 2, 1)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::E2BIG)
        );
        assert_eq!(fs::read_dir(root.0.join("tree")).unwrap().count(), 4);
        remove(&root.0, "tree").unwrap();
        assert!(!root.0.join("tree").exists());
    }
}
