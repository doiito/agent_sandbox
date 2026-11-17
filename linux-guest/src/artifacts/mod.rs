//! Bounded workspace export. The host constructs archive headers and hashes.
mod service;
mod tree;
pub(super) use service::Service;

const MAX_BYTES: u64 = 32 << 20;
const MAX_ENTRIES: usize = 1024;
const MAX_PATH_BYTES: usize = 64 << 10;
const MAX_DEPTH: usize = 16;
const DATA_BYTES: usize = 64 << 10;
const MANIFEST: &str = ".osv-artifact-manifest.json";
type Result<T> = std::result::Result<T, &'static str>;

fn valid_member(path: &str) -> bool {
    let first = path.split('/').next().unwrap_or("").as_bytes();
    !path.is_empty()
        && path.len() <= 1024
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path != MANIFEST
        && !(first.len() >= 2 && first[0].is_ascii_alphabetic() && first[1] == b':')
        && path.split('/').count() <= MAX_DEPTH
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && part.len() <= 255)
}

#[cfg(test)]
mod tests;
