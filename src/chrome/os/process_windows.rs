use super::{PipeReader, PipeWriter};
use std::ffi::{OsStr, OsString};
use std::mem::zeroed;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;

use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, WAIT_FAILED, WAIT_OBJECT_0};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::{
    CreateProcessW, WaitForSingleObject, INFINITE, PROCESS_INFORMATION, STARTUPINFOW,
};
use windows::core::{PCWSTR, PWSTR};

/// MSVC-specific stdio buffer structure for passing file handles to child processes.
/// This enables Chrome DevTools communication via file descriptors 3 and 4.
#[repr(C, packed)]
#[allow(dead_code)]
struct StdioBuffer5 {
    no_fds: u32,
    flags: [u8; 5],
    handles: [HANDLE; 5],
}

const FOPEN: u8 = 0x01;
const FPIPE: u8 = 0x08;
const FDEV: u8 = 0x40;

pub type Process = HANDLE;

/// Convert a `Process` (HANDLE) to a `usize` for storage
#[inline]
pub fn process_to_usize(p: Process) -> usize {
    p.0 as usize
}

/// Convert a `usize` back to a `Process` (HANDLE)
#[inline]
pub fn usize_to_process(u: usize) -> Process {
    HANDLE(u as *mut std::ffi::c_void)
}

fn to_wide_null(string: &str) -> Vec<u16> {
    OsStr::new(string)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub fn new_process(path: &str, args: &[&str]) -> Result<(Process, PipeReader, PipeWriter), String> {
    unsafe {
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: true.into(),
        };

        // Open NUL device for stdin/stdout/stderr redirection
        let nul_name = to_wide_null("NUL");
        let null_read = CreateFileW(
            PCWSTR::from_raw(nul_name.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Some(&sa),
            OPEN_EXISTING,
            Default::default(),
            None,
        )
        .map_err(|e| format!("CreateFileW (read) failed: {e}"))?;

        let null_write = CreateFileW(
            PCWSTR::from_raw(nul_name.as_ptr()),
            (FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Some(&sa),
            OPEN_EXISTING,
            Default::default(),
            None,
        )
        .map_err(|e| format!("CreateFileW (write) failed: {e}"))?;

        // Create pipes for fd 3 (Chrome reads from) and fd 4 (Chrome writes to)
        let mut readpipe3 = HANDLE::default();
        let mut writepipe3 = HANDLE::default();
        CreatePipe(&mut readpipe3, &mut writepipe3, Some(&sa), 0)
            .map_err(|e| format!("CreatePipe (pipe3) failed: {e}"))?;

        let mut readpipe4 = HANDLE::default();
        let mut writepipe4 = HANDLE::default();
        CreatePipe(&mut readpipe4, &mut writepipe4, Some(&sa), 0)
            .map_err(|e| format!("CreatePipe (pipe4) failed: {e}"))?;

        // Set up MSVC stdio buffer for fd 0-4
        let mut stdio_buffer = StdioBuffer5 {
            no_fds: 5,
            flags: [
                FOPEN | FDEV,  // fd 0: stdin -> NUL
                FOPEN | FDEV,  // fd 1: stdout -> NUL
                FOPEN | FDEV,  // fd 2: stderr -> NUL
                FOPEN | FPIPE, // fd 3: read pipe (Chrome reads from)
                FOPEN | FPIPE, // fd 4: write pipe (Chrome writes to)
            ],
            handles: [null_read, null_write, null_write, readpipe3, writepipe4],
        };

        let mut startupinfo: STARTUPINFOW = zeroed();
        startupinfo.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        startupinfo.cbReserved2 = std::mem::size_of::<StdioBuffer5>() as u16;
        startupinfo.lpReserved2 = &mut stdio_buffer as *mut StdioBuffer5 as *mut u8;

        let mut processinfo: PROCESS_INFORMATION = zeroed();

        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let mut cmd_str = make_command_line(&OsString::from(path), &args)
            .map_err(|e| format!("Failed to build command line: {e}"))?;

        CreateProcessW(
            None,
            Some(PWSTR::from_raw(cmd_str.as_mut_ptr())),
            None,
            None,
            true, // bInheritHandles
            Default::default(),
            None,
            None,
            &startupinfo,
            &mut processinfo,
        )
        .map_err(|e| format!("CreateProcessW failed: {e}"))?;

        // Close handles we don't need
        CloseHandle(processinfo.hThread)
            .map_err(|e| format!("CloseHandle (hThread) failed: {e}"))?;
        CloseHandle(readpipe3)
            .map_err(|e| format!("CloseHandle (readpipe3) failed: {e}"))?;
        CloseHandle(writepipe4)
            .map_err(|e| format!("CloseHandle (writepipe4) failed: {e}"))?;

        // Convert remaining handles to File for PipeReader/PipeWriter
        use std::fs::File;
        use std::os::windows::io::FromRawHandle;
        let writep = PipeWriter::new(File::from_raw_handle(writepipe3.0));
        let readp = PipeReader::new(File::from_raw_handle(readpipe4.0));

        Ok((processinfo.hProcess, readp, writep))
    }
}

pub fn exited(pid: Process) -> std::io::Result<bool> {
    unsafe {
        let result = WaitForSingleObject(pid, 0);
        if result == WAIT_OBJECT_0 {
            Ok(true)
        } else if result == WAIT_FAILED {
            Err(std::io::Error::from_raw_os_error(GetLastError().0 as i32))
        } else {
            Ok(false)
        }
    }
}

pub fn wait_proc(pid: Process) -> std::io::Result<()> {
    unsafe {
        let result = WaitForSingleObject(pid, INFINITE);
        if result == WAIT_FAILED {
            Err(std::io::Error::from_raw_os_error(GetLastError().0 as i32))
        } else {
            Ok(())
        }
    }
}

pub fn close_process_handle(p: Process) -> std::io::Result<()> {
    unsafe { CloseHandle(p).map_err(|e| std::io::Error::from_raw_os_error(e.code().0)) }
}

use std::io::{self, ErrorKind};

fn make_command_line(prog: &OsStr, args: &[OsString]) -> io::Result<Vec<u16>> {
    // Encode the command and arguments in a command line string such
    // that the spawned process may recover them using CommandLineToArgvW.
    let mut cmd: Vec<u16> = Vec::new();
    // Always quote the program name so CreateProcess doesn't interpret args as
    // part of the name if the binary wasn't found first time.
    append_arg(&mut cmd, prog, true)?;
    for arg in args {
        cmd.push(' ' as u16);
        append_arg(&mut cmd, arg, false)?;
    }
    cmd.push('\0' as u16);
    Ok(cmd)
}
fn append_arg(cmd: &mut Vec<u16>, arg: &OsStr, force_quotes: bool) -> io::Result<()> {
    // If an argument has 0 characters then we need to quote it to ensure
    // that it actually gets passed through on the command line or otherwise
    // it will be dropped entirely when parsed on the other end.
    ensure_no_nuls(arg)?;
    let wide_arg: Vec<u16> = arg.encode_wide().collect();
    let quote =
        force_quotes || wide_arg.iter().any(|c| *c == ' ' as u16 || *c == '\t' as u16) || wide_arg.is_empty();
    if quote {
        cmd.push('"' as u16);
    }

    let mut backslashes: usize = 0;
    for x in arg.encode_wide() {
        if x == '\\' as u16 {
            backslashes += 1;
        } else {
            if x == '"' as u16 {
                // Add n+1 backslashes to total 2n+1 before internal '"'.
                cmd.extend((0..=backslashes).map(|_| '\\' as u16));
            }
            backslashes = 0;
        }
        cmd.push(x);
    }

    if quote {
        // Add n backslashes to total 2n before ending '"'.
        cmd.extend((0..backslashes).map(|_| '\\' as u16));
        cmd.push('"' as u16);
    }
    Ok(())
}

fn ensure_no_nuls<T: AsRef<OsStr>>(str: T) -> io::Result<T> {
    if str.as_ref().encode_wide().any(|b| b == 0) {
        Err(io::Error::new(
            ErrorKind::InvalidInput,
            "nul byte found in provided data",
        ))
    } else {
        Ok(str)
    }
}
