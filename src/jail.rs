use std::path::Path;

#[derive(Debug)]
pub(crate) enum JailError {
    #[allow(dead_code)]
    Nofollow,
    Outside,
    HardLink,
    TooLarge,
    Read,
}

pub(crate) fn read_jailed(root: &str, requested: &str, max_bytes: u64) -> Result<Vec<u8>, JailError> {
    #[cfg(unix)]
    {
        read_unix(root, requested, max_bytes)
    }
    #[cfg(not(unix))]
    {
        let _ = (root, requested, max_bytes);
        Err(JailError::Nofollow)
    }
}

#[cfg(unix)]
fn read_unix(root: &str, requested: &str, max_bytes: u64) -> Result<Vec<u8>, JailError> {
    let base = std::fs::canonicalize(root).map_err(|_| JailError::Read)?;
    let requested_path = base.join(requested);
    let parent = requested_path.parent().ok_or(JailError::Outside)?;
    let parent_real = std::fs::canonicalize(parent).map_err(|_| JailError::Read)?;
    if escapes(&base, &parent_real) {
        return Err(JailError::Outside);
    }
    let leaf = requested_path.file_name().ok_or(JailError::Outside)?;
    if leaf == "." || leaf == ".." || leaf.is_empty() {
        return Err(JailError::Outside);
    }
    let path = parent_real.join(leaf);
    if escapes(&base, &path) || path == base {
        return Err(JailError::Outside);
    }
    let flags = rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC;
    let fd = rustix::fs::open(&path, flags, rustix::fs::Mode::empty()).map_err(|_| JailError::Read)?;
    let stat = rustix::fs::fstat(&fd).map_err(|_| JailError::Read)?;
    let kind = rustix::fs::FileType::from_raw_mode(stat.st_mode);
    if kind != rustix::fs::FileType::RegularFile {
        return Err(JailError::Read);
    }
    if u64::from(stat.st_nlink) > 1 {
        return Err(JailError::HardLink);
    }
    if stat.st_size < 0 || stat.st_size as u64 > max_bytes {
        return Err(JailError::TooLarge);
    }
    if stat.st_size == 0 {
        return Ok(Vec::new());
    }
    use std::io::Read;
    let mut file = std::fs::File::from(fd);
    let mut buf = vec![0u8; stat.st_size as usize];
    file.read_exact(&mut buf).map_err(|_| JailError::Read)?;
    Ok(buf)
}

fn escapes(base: &Path, target: &Path) -> bool {
    let Ok(relative) = target.strip_prefix(base) else {
        return true;
    };
    relative.components().any(|part| matches!(part, std::path::Component::ParentDir))
}
