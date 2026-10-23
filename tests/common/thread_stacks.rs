//! The call stack of every thread of a process tree: what a hung child is blocked in.
//!
//! A wait reason (`Wait LpcReply`) says only that a thread is inside a synchronous call to another
//! process. The stack names the call. Frames resolve to the nearest export of their module (no
//! symbol server is used), so a name is the exported function the code is in or just after.
#![allow(dead_code)]

use std::sync::Mutex;

/// `dbghelp` is single-threaded, and tests run in parallel.
static DBGHELP: Mutex<()> = Mutex::new(());

/// The stacks of all threads of `root` and of every process below it, as text.
#[cfg(target_arch = "x86_64")]
pub fn tree_stacks(root: u32) -> String {
    let _serial = DBGHELP.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut out = String::new();
    for pid in tree_pids(root) {
        out.push_str(&format!("process {pid}\n"));
        match process_stacks(pid) {
            Ok(text) => out.push_str(&text),
            Err(e) => out.push_str(&format!("  (no stacks: {e})\n")),
        }
    }
    out
}

#[cfg(not(target_arch = "x86_64"))]
pub fn tree_stacks(_root: u32) -> String {
    let _serial = DBGHELP.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    "(stacks are captured on x86_64 only)\n".to_owned()
}

#[cfg(target_arch = "x86_64")]
use imp::{process_stacks, tree_pids};

#[cfg(target_arch = "x86_64")]
mod imp {
    use std::ffi::c_void;
    use std::fmt::Write as _;

    use ssh_broker::winutil::OwnedHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Diagnostics::Debug::{
        ADDRESS64, AddrModeFlat, CONTEXT, CONTEXT_FULL_AMD64, GetThreadContext, IMAGEHLP_MODULEW64, STACKFRAME64,
        SYMBOL_INFOW, StackWalk64, SymCleanup, SymFromAddrW, SymFunctionTableAccess64, SymGetModuleBase64,
        SymGetModuleInfoW64, SymInitializeW, SymSetOptions,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
        TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, ResumeThread, SuspendThread,
        THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME,
    };
    use windows::core::PCWSTR;

    const IMAGE_FILE_MACHINE_AMD64: u32 = 0x8664;
    const SYMOPT_UNDNAME: u32 = 0x2;
    const SYMOPT_DEFERRED_LOADS: u32 = 0x4;
    /// Room for a symbol name after `SYMBOL_INFOW`, whose own `Name` holds one unit.
    const NAME_UNITS: usize = 256;

    /// `root` and every process below it.
    pub fn tree_pids(root: u32) -> Vec<u32> {
        let mut parents = Vec::new();
        // SAFETY: a snapshot handle, closed by `OwnedHandle`; `entry.dwSize` is set as required.
        unsafe {
            let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
                return vec![root];
            };
            let snapshot = OwnedHandle(snapshot);
            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };
            let mut next = Process32FirstW(snapshot.0, &mut entry);
            while next.is_ok() {
                parents.push((entry.th32ProcessID, entry.th32ParentProcessID));
                next = Process32NextW(snapshot.0, &mut entry);
            }
        }
        let mut tree = vec![root];
        let mut seen = 0;
        while seen < tree.len() {
            let parent = tree[seen];
            seen += 1;
            for &(pid, ppid) in &parents {
                if ppid == parent && !tree.contains(&pid) {
                    tree.push(pid);
                }
            }
        }
        tree
    }

    fn thread_ids(pid: u32) -> anyhow::Result<Vec<u32>> {
        let mut ids = Vec::new();
        // SAFETY: as in `tree_pids`.
        unsafe {
            let snapshot = OwnedHandle(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)?);
            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };
            let mut next = Thread32First(snapshot.0, &mut entry);
            while next.is_ok() {
                if entry.th32OwnerProcessID == pid {
                    ids.push(entry.th32ThreadID);
                }
                next = Thread32Next(snapshot.0, &mut entry);
            }
        }
        Ok(ids)
    }

    /// The stack of each thread of `pid`, one frame per line.
    pub fn process_stacks(pid: u32) -> anyhow::Result<String> {
        let threads = thread_ids(pid)?;
        // SAFETY: the handle is closed by `OwnedHandle`; `SymCleanup` pairs the `SymInitializeW`.
        let process = OwnedHandle(unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }?);
        unsafe {
            SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
            SymInitializeW(process.0, PCWSTR::null(), true)?;
        }
        let mut out = String::new();
        for tid in threads {
            let _ = writeln!(out, "  thread {tid}");
            match thread_stack(process.0, tid) {
                Ok(frames) => out.push_str(&frames),
                Err(e) => {
                    let _ = writeln!(out, "    (no stack: {e})");
                }
            }
        }
        // SAFETY: initialised above for this handle.
        let _ = unsafe { SymCleanup(process.0) };
        Ok(out)
    }

    /// The thread is suspended while its context is read and walked, and resumed after.
    fn thread_stack(process: HANDLE, tid: u32) -> anyhow::Result<String> {
        // SAFETY: the handle is closed by `OwnedHandle`.
        let thread = OwnedHandle(unsafe {
            OpenThread(
                THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                false,
                tid,
            )
        }?);
        // SAFETY: a valid thread handle with `THREAD_SUSPEND_RESUME`.
        if unsafe { SuspendThread(thread.0) } == u32::MAX {
            return Err(windows::core::Error::from_thread().into());
        }
        let frames = walk(process, thread.0);
        // SAFETY: as above.
        unsafe { ResumeThread(thread.0) };
        frames
    }

    // `StackWalk64` takes `extern "system"` callbacks; dbghelp's own are Rust-ABI declarations here.
    unsafe extern "system" fn function_table_access(process: HANDLE, base: u64) -> *mut c_void {
        // SAFETY: forwarded as dbghelp passes it.
        unsafe { SymFunctionTableAccess64(process, base) }
    }

    unsafe extern "system" fn module_base(process: HANDLE, address: u64) -> u64 {
        // SAFETY: forwarded as dbghelp passes it.
        unsafe { SymGetModuleBase64(process, address) }
    }

    #[repr(C, align(16))]
    struct AlignedContext(CONTEXT);

    fn walk(process: HANDLE, thread: HANDLE) -> anyhow::Result<String> {
        let mut context = AlignedContext(unsafe { std::mem::zeroed() });
        context.0.ContextFlags = CONTEXT_FULL_AMD64;
        // SAFETY: `context` is a valid, 16-byte aligned CONTEXT with `ContextFlags` set.
        unsafe { GetThreadContext(thread, &mut context.0) }?;
        let flat = |offset: u64| ADDRESS64 {
            Offset: offset,
            Segment: 0,
            Mode: AddrModeFlat,
        };
        let mut frame = STACKFRAME64 {
            AddrPC: flat(context.0.Rip),
            AddrFrame: flat(context.0.Rbp),
            AddrStack: flat(context.0.Rsp),
            ..Default::default()
        };
        let mut out = String::new();
        // StackWalk64 ends the walk itself: it fails when there is no caller left.
        loop {
            // SAFETY: `frame` and `context` are valid for the call; the routines are dbghelp's own.
            let more = unsafe {
                StackWalk64(
                    IMAGE_FILE_MACHINE_AMD64,
                    process,
                    thread,
                    &mut frame,
                    &mut context as *mut AlignedContext as *mut c_void,
                    None,
                    Some(function_table_access),
                    Some(module_base),
                    None,
                )
            };
            if !more.as_bool() || frame.AddrPC.Offset == 0 {
                break;
            }
            let _ = writeln!(out, "    {}", describe(process, frame.AddrPC.Offset));
        }
        Ok(out)
    }

    /// `module!export+0xoffset`, or `module+0xoffset` where no export is near, or the bare address.
    fn describe(process: HANDLE, address: u64) -> String {
        let mut module = IMAGEHLP_MODULEW64 {
            SizeOfStruct: std::mem::size_of::<IMAGEHLP_MODULEW64>() as u32,
            ..Default::default()
        };
        // SAFETY: `module` is a valid out-structure with its size set.
        let module_name = match unsafe { SymGetModuleInfoW64(process, address, &mut module) } {
            Ok(()) => {
                let len = module
                    .ModuleName
                    .iter()
                    .position(|&u| u == 0)
                    .unwrap_or(module.ModuleName.len());
                String::from_utf16_lossy(&module.ModuleName[..len])
            }
            Err(_) => return format!("{address:#x}"),
        };

        #[repr(C)]
        struct Symbol {
            info: SYMBOL_INFOW,
            more_name: [u16; NAME_UNITS],
        }
        let mut symbol: Symbol = unsafe { std::mem::zeroed() };
        symbol.info.SizeOfStruct = std::mem::size_of::<SYMBOL_INFOW>() as u32;
        symbol.info.MaxNameLen = NAME_UNITS as u32;
        let mut displacement = 0u64;
        // SAFETY: `symbol` has room for `MaxNameLen` units of name after the header.
        match unsafe { SymFromAddrW(process, address, Some(&mut displacement), &mut symbol.info) } {
            Ok(()) => {
                let name =
                    unsafe { std::slice::from_raw_parts(symbol.info.Name.as_ptr(), symbol.info.NameLen as usize) };
                format!("{module_name}!{}+{displacement:#x}", String::from_utf16_lossy(name))
            }
            Err(_) => format!("{module_name}+{:#x}", address - module.BaseOfImage),
        }
    }
}
