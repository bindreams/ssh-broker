//! The DLLs a Windows executable imports, read from its import table.
#![allow(dead_code)]

use std::io;
use std::path::Path;

fn bad(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("not a 64-bit PE image: {what}"))
}

fn u16_at(data: &[u8], at: usize) -> io::Result<u16> {
    data.get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| bad("truncated"))
}

fn u32_at(data: &[u8], at: usize) -> io::Result<u32> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| bad("truncated"))
}

/// The file offset of relative virtual address `rva`, through the section table.
fn offset_of(data: &[u8], sections: usize, count: usize, rva: u32) -> io::Result<usize> {
    for i in 0..count {
        let header = sections + i * 40;
        let size = u32_at(data, header + 8)?.max(u32_at(data, header + 16)?);
        let start = u32_at(data, header + 12)?;
        if (start..start.saturating_add(size)).contains(&rva) {
            return Ok((rva - start + u32_at(data, header + 20)?) as usize);
        }
    }
    Err(bad("an RVA outside every section"))
}

/// The DLL names in the import table of the 64-bit executable `path`, in table order and without
/// duplicates (compared ignoring case). Delay-loaded imports are not included.
pub fn imports(path: &Path) -> io::Result<Vec<String>> {
    let data = std::fs::read(path)?;
    if data.get(..2) != Some(b"MZ") {
        return Err(bad("no MZ header"));
    }
    let pe = u32_at(&data, 0x3C)? as usize;
    if data.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Err(bad("no PE signature"));
    }
    let section_count = u16_at(&data, pe + 6)? as usize;
    let optional_size = u16_at(&data, pe + 20)? as usize;
    let optional = pe + 24;
    if u16_at(&data, optional)? != 0x20B {
        return Err(bad("not a PE32+ optional header"));
    }
    // Data directory 1 is the import table; the directories start 112 bytes into a PE32+ header.
    let import_rva = u32_at(&data, optional + 112 + 8)?;
    let sections = optional + optional_size;
    if import_rva == 0 {
        return Ok(Vec::new());
    }

    let mut names: Vec<String> = Vec::new();
    let mut descriptor = offset_of(&data, sections, section_count, import_rva)?;
    // Each descriptor is 20 bytes; a zero one ends the table. The name RVA is at offset 12.
    while u32_at(&data, descriptor + 12)? != 0 {
        let name_at = offset_of(&data, sections, section_count, u32_at(&data, descriptor + 12)?)?;
        let tail = data.get(name_at..).ok_or_else(|| bad("truncated"))?;
        let end = tail
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| bad("unterminated name"))?;
        let name = String::from_utf8_lossy(&tail[..end]).into_owned();
        if !names.iter().any(|seen| seen.eq_ignore_ascii_case(&name)) {
            names.push(name);
        }
        descriptor += 20;
    }
    Ok(names)
}
