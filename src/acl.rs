//! acl: build & verify the socket-dir DACL — the sole access-control boundary.
//!
//! Windows AF_UNIX has no `SO_PEERCRED`, so the NTFS DACL on the socket directory IS
//! the access control: whoever can `connect()` gets a full interactive shell as the
//! user. We therefore set an explicit, **PROTECTED** (non-inherited) DACL granting
//! Full Control only to `{target user, SYSTEM, Administrators}`, and refuse to operate
//! unless a read-back **exactly** matches that set (fail-closed).
//!
//! The target user is resolved BY NAME (the account the agent's shell logs in as,
//! configured at setup), never the current process token — `apply` may run as SYSTEM
//! under the ONSTART self-heal task, so the current token is not the grantee.
//!
//! This module is Windows-only (`#[cfg(windows)] mod acl;`). API signatures were
//! source-verified against windows-0.62.2 (see verify-windows-acl-apis workflow).

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, CopySid,
    CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
    GetLengthSid, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    GetSecurityDescriptorOwner, GetTokenInformation, INHERITED_ACE, IsValidSid, LookupAccountNameW,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PRESENT, SE_DACL_PROTECTED, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER, TokenUser,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{BOOL, PCWSTR, PWSTR};

/// ACCESS_ALLOWED_ACE_TYPE (winnt.h) — stored raw in `ACE_HEADER.AceType` (a `u8`).
const ACE_TYPE_ALLOWED: u8 = 0;

/// Well-known SIDs in the allow-set besides the target user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WellKnown {
    System,
    Administrators,
}

/// An owned Windows security identifier (a copy of the raw SID bytes, so it outlives any
/// borrowed source buffer such as a token-information block).
pub struct Sid {
    bytes: Vec<u8>,
}

impl Sid {
    /// Copy an arbitrary (borrowed) `PSID` into an owned `Sid`.
    fn from_psid(psid: PSID) -> anyhow::Result<Sid> {
        unsafe {
            anyhow::ensure!(IsValidSid(psid).as_bool(), "not a valid SID");
            let len = GetLengthSid(psid);
            anyhow::ensure!(len > 0, "zero-length SID");
            let mut bytes = vec![0u8; len as usize];
            CopySid(len, PSID(bytes.as_mut_ptr() as *mut core::ffi::c_void), psid)?;
            Ok(Sid { bytes })
        }
    }

    /// A borrowed pointer to the owned SID bytes (valid while `self` lives).
    fn as_psid(&self) -> PSID {
        PSID(self.bytes.as_ptr() as *mut core::ffi::c_void)
    }

    /// SID of the user owning the current process token. Used by tests and by the
    /// interactive `apply` path; production provisioning resolves the grantee by name.
    pub fn current_user() -> anyhow::Result<Sid> {
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
            // Size probe: the first call is expected to fail with the needed length.
            let mut len = 0u32;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
            let mut buf = vec![0u8; len as usize];
            let info = GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                len,
                &mut len,
            );
            let _ = CloseHandle(token);
            info?;
            let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
            Sid::from_psid(token_user.User.Sid)
        }
    }

    /// A well-known SID (SYSTEM / BUILTIN\\Administrators).
    pub fn well_known(kind: WellKnown) -> anyhow::Result<Sid> {
        let which = match kind {
            WellKnown::System => WinLocalSystemSid,
            WellKnown::Administrators => WinBuiltinAdministratorsSid,
        };
        unsafe {
            let mut cb = 0u32;
            let _ = CreateWellKnownSid(which, None, None, &mut cb); // size probe -> Err
            anyhow::ensure!(cb > 0, "CreateWellKnownSid size probe returned 0");
            let mut bytes = vec![0u8; cb as usize];
            CreateWellKnownSid(
                which,
                None,
                Some(PSID(bytes.as_mut_ptr() as *mut core::ffi::c_void)),
                &mut cb,
            )?;
            Ok(Sid { bytes })
        }
    }

    /// Resolve a SID from an account name (e.g. "jdoe" or "DOMAIN\\user").
    pub fn lookup(account: &str) -> anyhow::Result<Sid> {
        let name: Vec<u16> = account.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            let mut cb_sid = 0u32;
            let mut cch_domain = 0u32;
            let mut sid_use = SID_NAME_USE(0);
            // Size probe (both SID and referenced-domain buffers).
            let _ = LookupAccountNameW(
                PCWSTR::null(),
                PCWSTR(name.as_ptr()),
                None,
                &mut cb_sid,
                None,
                &mut cch_domain,
                &mut sid_use,
            );
            anyhow::ensure!(cb_sid > 0, "account '{account}' could not be resolved to a SID");
            let mut bytes = vec![0u8; cb_sid as usize];
            // `.max(1)` so the buffer is never empty (an empty Vec's ptr is dangling, and
            // LookupAccountNameW requires a real referenced-domain buffer).
            let mut domain = vec![0u16; (cch_domain as usize).max(1)];
            LookupAccountNameW(
                PCWSTR::null(),
                PCWSTR(name.as_ptr()),
                Some(PSID(bytes.as_mut_ptr() as *mut core::ffi::c_void)),
                &mut cb_sid,
                Some(PWSTR(domain.as_mut_ptr())),
                &mut cch_domain,
                &mut sid_use,
            )?;
            Ok(Sid { bytes })
        }
    }

    /// The SID in SDDL string form ("S-1-5-…"), for embedding in a security descriptor.
    fn to_sddl(&self) -> anyhow::Result<String> {
        unsafe {
            let mut s = PWSTR::null();
            ConvertSidToStringSidW(self.as_psid(), &mut s)?;
            let text = s.to_string();
            let _ = LocalFree(Some(HLOCAL(s.0 as *mut core::ffi::c_void)));
            Ok(text?)
        }
    }
}

/// RAII for the `LocalAlloc`-backed security descriptor returned by the SDDL converter
/// and by `GetNamedSecurityInfoW`: frees it exactly once on every exit path.
struct LocalSd(PSECURITY_DESCRIPTOR);
impl Drop for LocalSd {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.0)));
            }
        }
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// Apply the explicit, PROTECTED owner-only DACL (`{target_user, SYSTEM, Administrators}`
/// Full Control, target_user as owner) to `dir`, removing any inherited or broader access.
pub fn harden_dir(dir: &Path, target_user: &Sid) -> anyhow::Result<()> {
    let target = target_user.to_sddl()?;
    // P = protected (no inheritance); FA = Full; SY = SYSTEM, BA = BUILTIN\Administrators.
    let sddl = format!("O:{target}D:P(A;;FA;;;{target})(A;;FA;;;SY)(A;;FA;;;BA)");
    let sddl_w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let path_w = wide(dir);
    unsafe {
        let mut psd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &mut psd,
            None,
        )?;
        let _sd = LocalSd(psd); // freed on every path below

        let mut dacl_present = BOOL(0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut dacl_defaulted = BOOL(0);
        GetSecurityDescriptorDacl(psd, &mut dacl_present, &mut dacl, &mut dacl_defaulted)?;

        let mut owner = PSID::default();
        let mut owner_defaulted = BOOL(0);
        GetSecurityDescriptorOwner(psd, &mut owner, &mut owner_defaulted)?;

        // PROTECTED | DACL makes the new DACL non-inherited; also set the owner.
        SetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            Some(owner),
            None,
            Some(dacl as *const ACL),
            None,
        )
        .ok()?;
        Ok(())
    }
}

/// Read `dir`'s DACL + owner back and return `true` iff it is EXACTLY the locked-down
/// allow-set: a PRESENT, PROTECTED DACL whose ACEs are precisely Full-Control ALLOWs for
/// `{target_user, SYSTEM, Administrators}` (each once), owner within the allow-set, and no
/// inherited or DENY ACEs. Anything else (incl. a NULL/absent DACL) returns `false` —
/// fail-closed.
pub fn verify_dir_acl(dir: &Path, target_user: &Sid) -> anyhow::Result<bool> {
    let system = Sid::well_known(WellKnown::System)?;
    let admins = Sid::well_known(WellKnown::Administrators)?;
    let expected = [target_user, &system, &admins];
    let path_w = wide(dir);

    unsafe {
        let mut psd = PSECURITY_DESCRIPTOR::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut owner = PSID::default();
        let rc = GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            &mut psd,
        );
        let _sd = LocalSd(psd);
        rc.ok()?;

        // A NULL/absent DACL means unrestricted access — never acceptable.
        if dacl.is_null() {
            return Ok(false);
        }

        // The DACL must be both PRESENT and PROTECTED. An *absent* DACL (present bit
        // clear) means "everyone, full access" — reject it explicitly, not just the
        // null-pointer case. PROTECTED means no inheritance from the parent dir.
        let mut control = 0u16;
        let mut revision = 0u32;
        GetSecurityDescriptorControl(psd, &mut control, &mut revision)?;
        if control & SE_DACL_PRESENT.0 == 0 || control & SE_DACL_PROTECTED.0 == 0 {
            return Ok(false);
        }

        // Owner must be a valid SID in the allow-set. Guard validity before EqualSid
        // (which is unsafe and assumes valid SID pointers).
        if owner.is_invalid() || !IsValidSid(owner).as_bool() {
            return Ok(false);
        }
        let owner_ok = expected.iter().any(|s| EqualSid(owner, s.as_psid()).is_ok());
        if !owner_ok {
            return Ok(false);
        }

        let mut size_info = ACL_SIZE_INFORMATION::default();
        GetAclInformation(
            dacl,
            &mut size_info as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )?;

        let mut seen = [false; 3];
        let mut allowed_count = 0u32;
        for i in 0..size_info.AceCount {
            let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
            GetAce(dacl, i, &mut ace)?;
            let header = &*(ace as *const ACE_HEADER);

            // Any inherited ACE means the dir is not the locked-down explicit set.
            if header.AceFlags & (INHERITED_ACE.0 as u8) != 0 {
                return Ok(false);
            }
            // Only ALLOW ACEs are permitted; a DENY (or any other type) fails closed.
            if header.AceType != ACE_TYPE_ALLOWED {
                return Ok(false);
            }

            // Defensive: confirm the ACE body is large enough to contain Mask + a SID
            // start before dereferencing it (the on-disk DACL is treated as untrusted).
            if (header.AceSize as usize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>() {
                return Ok(false);
            }
            let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
            // Each grant must be exactly Full Control (SDDL "FA" == FILE_ALL_ACCESS).
            if allowed.Mask != FILE_ALL_ACCESS.0 {
                return Ok(false);
            }
            let trustee = PSID(&allowed.SidStart as *const u32 as *mut core::ffi::c_void);

            let mut matched = false;
            for (idx, exp) in expected.iter().enumerate() {
                if IsValidSid(trustee).as_bool() && EqualSid(trustee, exp.as_psid()).is_ok() {
                    if seen[idx] {
                        return Ok(false); // duplicate ACE for the same grantee
                    }
                    seen[idx] = true;
                    matched = true;
                    break;
                }
            }
            if !matched {
                return Ok(false); // an unexpected grantee (e.g. Everyone/Users)
            }
            allowed_count += 1;
        }

        // Exactly the three expected grantees, each present once, nothing else.
        Ok(allowed_count == 3 && seen.iter().all(|&b| b))
    }
}

#[cfg(test)]
#[path = "acl_tests.rs"]
mod acl_tests;
