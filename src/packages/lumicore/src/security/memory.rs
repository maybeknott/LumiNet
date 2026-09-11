//! # Process Memory Search & Replace Engine
//!
//! Exposes APIs to scan process memory maps and perform multi-pattern string replacement
//! in-memory. Extracted and refined from ISpooferMotion-main.

use std::io;
#[cfg(target_os = "linux")]
use std::io::{Read, Seek, SeekFrom, Write};

/// Struct representing a memory region committed in a process address space
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub region_size: usize,
    pub is_writable: bool,
}

/// Retrieve writable committed memory regions of a process.
#[cfg(target_os = "windows")]
pub fn get_process_regions(pid: u32) -> io::Result<Vec<MemoryRegion>> {
    use std::ffi::c_void;
    use windows_sys::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }

    let mut regions = Vec::new();
    let mut address: usize = 0;
    let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

    loop {
        let size = unsafe {
            VirtualQueryEx(
                handle,
                address as *const c_void,
                &mut mem_info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if size == 0 {
            break;
        }

        if mem_info.State == MEM_COMMIT {
            let is_writable =
                mem_info.Protect == PAGE_READWRITE || mem_info.Protect == PAGE_EXECUTE_READWRITE;
            let is_readable = is_writable
                || mem_info.Protect == PAGE_READONLY
                || mem_info.Protect == PAGE_EXECUTE_READ;

            if is_readable {
                regions.push(MemoryRegion {
                    base_address: mem_info.BaseAddress as usize,
                    region_size: mem_info.RegionSize,
                    is_writable,
                });
            }
        }

        let next_address = address.saturating_add(mem_info.RegionSize);
        if next_address <= address {
            break;
        }
        address = next_address;
    }

    unsafe {
        windows_sys::Win32::Foundation::CloseHandle(handle);
    }
    Ok(regions)
}

/// Retrieve writable committed memory regions of a process.
#[cfg(target_os = "linux")]
pub fn get_process_regions(pid: u32) -> io::Result<Vec<MemoryRegion>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let maps_path = format!("/proc/{}/maps", pid);
    let file = File::open(maps_path)?;
    let reader = BufReader::new(file);
    let mut regions = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let range: Vec<&str> = parts[0].split('-').collect();
            if range.len() == 2 {
                let start = usize::from_str_radix(range[0], 16).unwrap_or(0);
                let end = usize::from_str_radix(range[1], 16).unwrap_or(0);
                let perms = parts[1];
                let is_writable = perms.contains('w');
                let is_readable = perms.contains('r');

                if is_readable && start < end {
                    regions.push(MemoryRegion {
                        base_address: start,
                        region_size: end - start,
                        is_writable,
                    });
                }
            }
        }
    }

    Ok(regions)
}

/// Retrieve writable committed memory regions of a process.
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn get_process_regions(_pid: u32) -> io::Result<Vec<MemoryRegion>> {
    Ok(Vec::new())
}

fn find_all_occurrences(buffer: &[u8], target: &[u8]) -> Vec<usize> {
    let mut indices = Vec::new();
    if target.is_empty() || buffer.len() < target.len() {
        return indices;
    }
    for i in 0..=buffer.len() - target.len() {
        if &buffer[i..i + target.len()] == target {
            indices.push(i);
        }
    }
    indices
}

/// Scans process memory and replaces all occurrences of a target byte sequence with a replacement.
/// Returns the number of replacements made.
#[cfg(target_os = "windows")]
pub fn scan_and_replace(pid: u32, target: &[u8], replacement: &[u8]) -> io::Result<usize> {
    use std::ffi::c_void;
    use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
        PROCESS_VM_WRITE,
    };

    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            0,
            pid,
        )
    };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }

    let regions = get_process_regions(pid)?;
    let mut total_replacements = 0;

    for region in regions {
        if !region.is_writable {
            continue;
        }

        let mut buffer = vec![0u8; region.region_size];
        let mut bytes_read = 0;
        let success = unsafe {
            ReadProcessMemory(
                handle,
                region.base_address as *const c_void,
                buffer.as_mut_ptr() as *mut c_void,
                region.region_size,
                &mut bytes_read,
            )
        };

        if success != 0 && bytes_read > 0 {
            let matches = find_all_occurrences(&buffer[..bytes_read], target);

            if !matches.is_empty() {
                let mut region_replacements = 0;
                for start in matches {
                    let mut bytes_written = 0;
                    let success_write = unsafe {
                        WriteProcessMemory(
                            handle,
                            (region.base_address + start) as *mut c_void,
                            replacement.as_ptr() as *const c_void,
                            replacement.len(),
                            &mut bytes_written,
                        )
                    };
                    if success_write != 0 && bytes_written == replacement.len() {
                        region_replacements += 1;
                    }
                }
                total_replacements += region_replacements;
            }
        }
    }

    unsafe {
        windows_sys::Win32::Foundation::CloseHandle(handle);
    }
    Ok(total_replacements)
}

/// Scans process memory and replaces all occurrences of a target byte sequence with a replacement.
/// Returns the number of replacements made.
#[cfg(target_os = "linux")]
pub fn scan_and_replace(pid: u32, target: &[u8], replacement: &[u8]) -> io::Result<usize> {
    let regions = get_process_regions(pid)?;
    let mut mem_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("/proc/{}/mem", pid))?;

    let mut total_replacements = 0;

    for region in regions {
        if !region.is_writable {
            continue;
        }

        let mut buffer = vec![0u8; region.region_size];
        if mem_file
            .seek(SeekFrom::Start(region.base_address as u64))
            .is_ok()
        {
            if mem_file.read_exact(&mut buffer).is_ok() {
                let matches = find_all_occurrences(&buffer, target);

                if !matches.is_empty() {
                    let mut region_replacements = 0;
                    for start in matches {
                        if mem_file
                            .seek(SeekFrom::Start((region.base_address + start) as u64))
                            .is_ok()
                        {
                            if mem_file.write_all(replacement).is_ok() {
                                region_replacements += 1;
                            }
                        }
                    }
                    total_replacements += region_replacements;
                }
            }
        }
    }

    Ok(total_replacements)
}

/// Scans process memory and replaces all occurrences of a target byte sequence with a replacement.
/// Returns the number of replacements made.
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn scan_and_replace(_pid: u32, _target: &[u8], _replacement: &[u8]) -> io::Result<usize> {
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_process_regions() {
        let pid = std::process::id();
        let regions = get_process_regions(pid);
        assert!(regions.is_ok());
        let regions = regions.unwrap();
        assert!(!regions.is_empty());
    }

    #[test]
    fn test_scan_and_replace() {
        let pid = std::process::id();
        let target = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let replacement = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];

        let result = scan_and_replace(pid, &target, &replacement);

        #[cfg(any(target_os = "windows", target_os = "linux"))]
        {
            assert!(result.is_ok());
            let _count = result.unwrap();
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            assert!(result.is_ok());
        }
    }
}
