//! acl: build & verify the DACLs of a user's socket directory and socket file.
//!
//! Windows AF_UNIX has no `SO_PEERCRED`, so NTFS access control is what decides who can
//! `connect()`, and whoever can gets a full interactive shell as the user. Two objects carry it:
//!
//! - The socket **file's** DACL decides who can connect. Traverse checks on the folders above it
//!   are bypassed by `SeChangeNotifyPrivilege`, which every ordinary user holds, so the folder's
//!   DACL does not stop a second user who knows the path.
//! - The socket **directory's** DACL decides who can create, replace or delete the socket.
//!
//! Both must grant Full Control only to `{user, SYSTEM, Administrators}`. The directory gets an
//! explicit, **PROTECTED** DACL whose ACEs are inheritable, so the socket file (and the lock
//! file, and the logs folder) is born with exactly that set instead of the creating token's
//! default DACL. [`verify_dir_acl`] and [`verify_file_acl`] read the DACLs back and refuse
//! anything but an exact match (fail-closed).
//!
//! The user is the account the agent runs as: the agent lives in that user's profile, so its own
//! token is the grantee.
//!
//! The install directory (`C:\ProgramData\ssh-broker`) is the other half of the boundary: the
//! agent runs the exe in it as the user, so a directory a standard user can write to is a local
//! privilege escalation.
//!
//! This module is Windows-only (`#[cfg(windows)] mod acl;`). API signatures were
//! source-verified against windows-0.62.2 (see verify-windows-acl-apis workflow).

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use anyhow::Context;
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT, NTCREATEFILE_CREATE_DISPOSITION,
    NTCREATEFILE_CREATE_OPTIONS, NtCreateFile,
};
use windows::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, HANDLE, HLOCAL, LocalFree, NTSTATUS, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError,
    STATUS_ACCESS_DENIED, STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
    UNICODE_STRING,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
    GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, CONTAINER_INHERIT_ACE, CopySid,
    CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, INHERITED_ACE, IsValidSid, LookupAccountNameW, LookupAccountSidW, OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PRESENT, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
    SID_NAME_USE, TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinBuiltinUsersSid,
    WinLocalSystemSid,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, FILE_ACCESS_RIGHTS, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFileInformationByHandle, READ_CONTROL,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::System::Threading::OpenProcessToken;
use windows::Win32::System::WindowsProgramming::FILE_CREATED;
use windows::core::{BOOL, HRESULT, PCWSTR, PWSTR};

use crate::winutil::OwnedHandle;

mod admin_file;
pub use admin_file::{admin_only_file_problem, ensure_admin_only_file};
mod private_dir;
pub use private_dir::{
    DirHandle, Missing, Refused, ensure_private_dir, open_dir, open_existing_file, open_existing_private_dir,
    open_log_file, open_private_dir, open_root,
};

/// ACCESS_ALLOWED_ACE_TYPE (winnt.h) — stored raw in `ACE_HEADER.AceType` (a `u8`).
const ACE_TYPE_ALLOWED: u8 = 0;

/// Well-known SIDs in the allow-set besides the target user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WellKnown {
    System,
    Administrators,
    Users,
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
        Sid::of_token(crate::winutil::own_token()?.0)
    }

    /// SID of the user owning the token of `process`, which needs `PROCESS_QUERY_LIMITED_INFORMATION`.
    pub fn of_process(process: HANDLE) -> anyhow::Result<Sid> {
        let mut token = HANDLE::default();
        // SAFETY: a valid out-pointer; the handle is closed by `OwnedHandle`.
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token)? };
        let token = OwnedHandle(token);
        Sid::of_token(token.0)
    }

    /// SID of the user `token` belongs to, which needs `TOKEN_QUERY`.
    pub fn of_token(token: HANDLE) -> anyhow::Result<Sid> {
        let buf = crate::winutil::token_information(token, TokenUser).context("read the token's user")?;
        anyhow::ensure!(
            buf.size() >= size_of::<TOKEN_USER>(),
            "the token's user is {} bytes, shorter than its header",
            buf.size()
        );
        // SAFETY: the buffer holds a `TOKEN_USER` (checked above), 8-aligned, whose SID lies inside it.
        let sid = unsafe { buf.as_ptr::<TOKEN_USER>().read() }.User.Sid;
        Sid::from_psid(sid)
    }

    /// A well-known SID (SYSTEM / BUILTIN\\Administrators / BUILTIN\\Users).
    pub fn well_known(kind: WellKnown) -> anyhow::Result<Sid> {
        let which = match kind {
            WellKnown::System => WinLocalSystemSid,
            WellKnown::Administrators => WinBuiltinAdministratorsSid,
            WellKnown::Users => WinBuiltinUsersSid,
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

    /// `DOMAIN\name (S-1-5-...)` as far as the account database resolves it, else the SID
    /// string. For report rows and error messages; never fails.
    pub fn describe(&self) -> String {
        describe_sid(self.as_psid())
    }

    /// `(domain, name)` the account database holds for this SID.
    pub fn account(&self) -> anyhow::Result<(String, String)> {
        account_of_sid(self.as_psid())
            .ok_or_else(|| anyhow::anyhow!("no account is known by the SID {}", self.describe()))
    }

    /// The SID in SDDL string form ("S-1-5-…"), for embedding in a security descriptor.
    pub fn to_sddl(&self) -> anyhow::Result<String> {
        sid_to_string(self.as_psid())
    }
}

fn sid_to_string(psid: PSID) -> anyhow::Result<String> {
    unsafe {
        let mut s = PWSTR::null();
        ConvertSidToStringSidW(psid, &mut s)?;
        let text = s.to_string();
        let _ = LocalFree(Some(HLOCAL(s.0 as *mut core::ffi::c_void)));
        Ok(text?)
    }
}

/// `DOMAIN\\name (S-1-5-...)` for a valid SID, as far as the account database resolves it, for an
/// error message. Never fails: whatever cannot be read is left out.
fn describe_sid(psid: PSID) -> String {
    unsafe {
        if psid.is_invalid() || !IsValidSid(psid).as_bool() {
            return "<none>".into();
        }
        let text = sid_to_string(psid).unwrap_or_else(|_| "<unprintable SID>".into());
        let Some((domain, name)) = account_of_sid(psid) else {
            return text;
        };
        if domain.is_empty() {
            format!("{name} ({text})")
        } else {
            format!("{domain}\\{name} ({text})")
        }
    }
}

/// `(domain, name)` the account database holds for a valid `psid`, or `None` if it holds none.
fn account_of_sid(psid: PSID) -> Option<(String, String)> {
    unsafe {
        let (mut cch_name, mut cch_domain) = (0u32, 0u32);
        let mut sid_use = SID_NAME_USE(0);
        let _ = LookupAccountSidW(
            PCWSTR::null(),
            psid,
            None,
            &mut cch_name,
            None,
            &mut cch_domain,
            &mut sid_use,
        ); // size probe -> Err
        if cch_name == 0 {
            return None;
        }
        let mut name = vec![0u16; cch_name as usize];
        let mut domain = vec![0u16; (cch_domain as usize).max(1)];
        LookupAccountSidW(
            PCWSTR::null(),
            psid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut cch_name,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut cch_domain,
            &mut sid_use,
        )
        .ok()?;
        Some((
            String::from_utf16_lossy(&domain[..cch_domain as usize]),
            String::from_utf16_lossy(&name[..cch_name as usize]),
        ))
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

/// The DACL of a user's private directory in SDDL: protected (no inheritance from the parent),
/// `{user, SYSTEM, Administrators}` Full Control, inherited by the files and folders made below
/// (`OICI`). No owner: a creation leaves it to the creating token.
fn private_dir_dacl_sddl(user: &Sid) -> anyhow::Result<String> {
    let user = user.to_sddl()?;
    Ok(format!("D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"))
}

/// Apply the explicit, PROTECTED owner-only DACL (`{target_user, SYSTEM, Administrators}`
/// Full Control, target_user as owner) to `dir`, removing any inherited or broader access. The
/// ACEs are inheritable (`OI|CI`) so everything created inside is born with the same set.
///
/// A fixture for tests that need a folder of this shape.
#[cfg(test)]
pub fn harden_dir(dir: &Path, target_user: &Sid) -> anyhow::Result<()> {
    use windows::Win32::Security::Authorization::SetNamedSecurityInfoW;
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    let sd = descriptor_from_sddl(&format!(
        "O:{}{}",
        target_user.to_sddl()?,
        private_dir_dacl_sddl(target_user)?
    ))?;
    let psd = sd.0;
    let path_w = wide(dir);
    unsafe {
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

/// One ALLOW ACE a DACL must contain, once, and nothing else.
struct Grant<'a> {
    sid: &'a Sid,
    /// The exact access mask the ACE must carry.
    mask: u32,
    /// The exact `AceFlags` the ACE must carry, or `None` to allow any flags but `INHERITED_ACE`.
    flags: Option<u8>,
}

/// Whether a DACL must be the object's own protected set, or may be the set it inherited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Inheritance {
    /// Protected, and no ACE inherited: a directory this module hardened.
    Explicit,
    /// Protected or not, inherited ACEs allowed: a file born inside such a directory.
    Inherited,
}

/// A security descriptor read back from an object: the DACL and owner point into `sd`.
struct Security {
    sd: LocalSd,
    dacl: *mut ACL,
    owner: PSID,
}

impl Security {
    fn from_path(path: &Path) -> anyhow::Result<Security> {
        let path_w = wide(path);
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
            let sd = LocalSd(psd);
            rc.ok()?;
            Ok(Security { sd, dacl, owner })
        }
    }

    /// Read from an open handle.
    fn from_handle(handle: HANDLE) -> anyhow::Result<Security> {
        unsafe {
            let mut psd = PSECURITY_DESCRIPTOR::default();
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut owner = PSID::default();
            let rc = GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                Some(&mut dacl),
                None,
                Some(&mut psd),
            );
            let sd = LocalSd(psd);
            rc.ok()?;
            Ok(Security { sd, dacl, owner })
        }
    }

    /// `true` iff the owner is a valid SID that is one of `set`.
    fn owner_in(&self, set: &[&Sid]) -> anyhow::Result<bool> {
        // Guard validity before copying (`from_psid` and `EqualSid` assume valid SID pointers).
        if self.owner.is_invalid() || !unsafe { IsValidSid(self.owner) }.as_bool() {
            return Ok(false);
        }
        Ok(is_in(&Sid::from_psid(self.owner)?, set))
    }

    /// `true` iff the DACL is EXACTLY the given policy: PRESENT and PROTECTED, its ACEs
    /// precisely `grants` (each once), no inherited, DENY or other ACEs. Anything else, including a
    /// NULL or absent DACL, is `false`: fail-closed.
    fn dacl_matches(&self, grants: &[Grant]) -> anyhow::Result<bool> {
        self.dacl_matches_as(grants, Inheritance::Explicit)
    }

    /// [`Self::dacl_matches`] with the inheritance state the policy allows.
    fn dacl_matches_as(&self, grants: &[Grant], inheritance: Inheritance) -> anyhow::Result<bool> {
        unsafe {
            // A NULL/absent DACL means unrestricted access — never acceptable.
            if self.dacl.is_null() {
                return Ok(false);
            }

            // The DACL must be both PRESENT and PROTECTED. An *absent* DACL (present bit
            // clear) means "everyone, full access" — reject it explicitly, not just the
            // null-pointer case. PROTECTED means no inheritance from the parent dir.
            let mut control = 0u16;
            let mut revision = 0u32;
            GetSecurityDescriptorControl(self.sd.0, &mut control, &mut revision)?;
            if control & SE_DACL_PRESENT.0 == 0 {
                return Ok(false);
            }
            if inheritance == Inheritance::Explicit && control & SE_DACL_PROTECTED.0 == 0 {
                return Ok(false);
            }

            let mut size_info = ACL_SIZE_INFORMATION::default();
            GetAclInformation(
                self.dacl,
                &mut size_info as *mut _ as *mut core::ffi::c_void,
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )?;

            let mut seen = vec![false; grants.len()];
            let mut allowed_count = 0usize;
            for i in 0..size_info.AceCount {
                let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                GetAce(self.dacl, i, &mut ace)?;
                let header = &*(ace as *const ACE_HEADER);

                // An explicit policy takes no inherited ACE: the dir is not the locked-down set.
                let inherited = header.AceFlags & (INHERITED_ACE.0 as u8) != 0;
                if inherited && inheritance == Inheritance::Explicit {
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
                let trustee = PSID(&allowed.SidStart as *const u32 as *mut core::ffi::c_void);

                let mut matched = false;
                for (idx, grant) in grants.iter().enumerate() {
                    if IsValidSid(trustee).as_bool() && EqualSid(trustee, grant.sid.as_psid()).is_ok() {
                        if seen[idx] {
                            return Ok(false); // duplicate ACE for the same grantee
                        }
                        // Each grant must carry exactly the mask (and flags) the policy names.
                        // `INHERITED_ACE` is judged above; the rest of the flags are the policy's.
                        let flags = header.AceFlags & !(INHERITED_ACE.0 as u8);
                        if allowed.Mask != grant.mask || grant.flags.is_some_and(|f| flags != f) {
                            return Ok(false);
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

            // Exactly the expected grantees, each present once, nothing else.
            Ok(allowed_count == grants.len() && seen.iter().all(|&b| b))
        }
    }
}

/// `AceFlags` of the directory's ACEs: `OI|CI`, and not `INHERITED_ACE`.
const PRIVATE_DIR_ACE_FLAGS: u8 = (OBJECT_INHERIT_ACE.0 | CONTAINER_INHERIT_ACE.0) as u8;

/// The three Full-Control grants of a user's private directory. `flags` is what the directory
/// itself must carry; a file inside takes any flags.
fn private_grants<'a>(user: &'a Sid, system: &'a Sid, admins: &'a Sid, flags: Option<u8>) -> [Grant<'a>; 3] {
    let full = |sid| Grant {
        sid,
        mask: FILE_ALL_ACCESS.0,
        flags,
    };
    [full(user), full(system), full(admins)]
}

/// Read `dir`'s DACL + owner back and return `true` iff it is EXACTLY the locked-down
/// allow-set: a PRESENT, PROTECTED DACL whose ACEs are precisely inheritable (`OI|CI`)
/// Full-Control ALLOWs for `{target_user, SYSTEM, Administrators}` (each once), owner within the
/// allow-set, and no inherited or DENY ACEs. Anything else (incl. a NULL/absent DACL) returns
/// `false` — fail-closed. The ACEs must be inheritable: a directory whose ACEs do not reach the
/// socket file leaves the file with the creator's default DACL.
pub fn verify_dir_acl(dir: &Path, target_user: &Sid) -> anyhow::Result<bool> {
    dir_policy_holds(&Security::from_path(dir)?, target_user)
}

/// [`verify_dir_acl`] on an already-read security descriptor.
fn dir_policy_holds(security: &Security, user: &Sid) -> anyhow::Result<bool> {
    let (owner_ok, acl_ok) = dir_policy(security, user)?;
    Ok(owner_ok && acl_ok)
}

/// Whether the owner and the ACL of a private directory are each what they must be, for a caller
/// that says which one is not.
fn dir_policy(security: &Security, user: &Sid) -> anyhow::Result<(bool, bool)> {
    let system = Sid::well_known(WellKnown::System)?;
    let admins = Sid::well_known(WellKnown::Administrators)?;
    Ok((
        security.owner_in(&[user, &system, &admins])?,
        security.dacl_matches(&private_grants(user, &system, &admins, Some(PRIVATE_DIR_ACE_FLAGS)))?,
    ))
}

/// `true` iff `file` (the socket, the lock, a folder made inside a hardened directory) grants
/// Full Control to exactly `{user, SYSTEM, Administrators}` and to no one else, with an owner in
/// that set. The ACEs may be inherited, which is how such a file is born. Anything else is
/// `false`: fail-closed. For the socket this is the check that decides who can connect.
pub fn verify_file_acl(file: &Path, user: &Sid) -> anyhow::Result<bool> {
    file_policy_holds(&Security::from_path(file)?, user)
}

/// [`verify_file_acl`] on an already-read security descriptor.
fn file_policy_holds(security: &Security, user: &Sid) -> anyhow::Result<bool> {
    let system = Sid::well_known(WellKnown::System)?;
    let admins = Sid::well_known(WellKnown::Administrators)?;
    Ok(security.owner_in(&[user, &system, &admins])?
        && security.dacl_matches_as(&private_grants(user, &system, &admins, None), Inheritance::Inherited)?)
}

// install directory ====================================================================

/// The install directory's security descriptor: owner Administrators; protected DACL; SYSTEM and
/// Administrators Full Control and `BUILTIN\Users` read and execute, all inherited by children.
/// Handed to `CreateDirectoryW`, so the directory
/// never exists with any other DACL.
const INSTALL_DIR_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)";

/// `AceFlags` of every ACE in [`INSTALL_DIR_SDDL`]: `OI|CI`, and not `INHERITED_ACE`.
const INSTALL_ACE_FLAGS: u8 = (OBJECT_INHERIT_ACE.0 | CONTAINER_INHERIT_ACE.0) as u8;

/// Open `dir` itself (never a reparse target) with only the rights to read its ACL and
/// attributes, so every later answer is about the object opened and not about whatever the path
/// names a moment later. `None` if the object refuses even that (access denied).
///
/// Not `CreateFileW`: it always adds `SYNCHRONIZE` to the request, so a deny ACE covering
/// `SYNCHRONIZE` (`icacls /deny (W)` does) would fail the open before the ACL is read.
fn open_for_inspection(dir: &Path) -> anyhow::Result<Option<OwnedHandle>> {
    let name = nt_path(dir)?;
    let made = nt_create(
        None,
        &name,
        READ_CONTROL.0 | FILE_READ_ATTRIBUTES.0,
        FILE_OPEN,
        FILE_OPEN_FOR_BACKUP_INTENT.0 | FILE_OPEN_REPARSE_POINT.0,
        None,
    )?;
    match classify_open(made.status) {
        OpenOutcome::Opened => Ok(Some(OwnedHandle(made.handle))),
        OpenOutcome::Denied => Ok(None),
        OpenOutcome::Missing | OpenOutcome::NotADirectory | OpenOutcome::Failed(_) => {
            Err(status_error(made.status)).with_context(|| format!("open {}", dir.display()))
        }
    }
}

/// What `NtCreateFile` made of a name: its status, and the handle, which is valid only if the status
/// is not an error and which the caller then owns. [`classify_open`] says what the status means.
struct Made {
    status: NTSTATUS,
    handle: HANDLE,
    /// The call made the object: it did not exist.
    created: bool,
}

/// Open or make `name` (UTF-16, no terminator), an NT path when `root` is `None` and else one name
/// below `root`, sharing read, write and delete; a made object gets `descriptor`. `Err` is a name too
/// long to pass.
fn nt_create(
    root: Option<HANDLE>,
    name: &[u16],
    access: u32,
    disposition: NTCREATEFILE_CREATE_DISPOSITION,
    options: u32,
    descriptor: Option<PSECURITY_DESCRIPTOR>,
) -> anyhow::Result<Made> {
    let mut handle = HANDLE::default();
    let mut io = IO_STATUS_BLOCK::default();
    let status = with_attributes(root, name, descriptor, |attributes| {
        // SAFETY: every pointer is to a local that outlives the call.
        unsafe {
            NtCreateFile(
                &mut handle,
                FILE_ACCESS_RIGHTS(access),
                attributes,
                &mut io,
                None,
                FILE_FLAGS_AND_ATTRIBUTES(FILE_ATTRIBUTE_NORMAL.0),
                FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
                disposition,
                NTCREATEFILE_CREATE_OPTIONS(options),
                None,
                0,
            )
        }
    })?;
    Ok(Made {
        status,
        handle,
        created: io.Information == FILE_CREATED as usize,
    })
}

/// Run `call` with the `OBJECT_ATTRIBUTES` that name `name` (UTF-16, no terminator) under `root`, or
/// as an NT path without it, and carry `descriptor` into a creation. Names compare without case.
fn with_attributes<R>(
    root: Option<HANDLE>,
    name: &[u16],
    descriptor: Option<PSECURITY_DESCRIPTOR>,
    call: impl FnOnce(&OBJECT_ATTRIBUTES) -> R,
) -> anyhow::Result<R> {
    let mut units = name.to_vec();
    let bytes = u16::try_from(units.len() * 2).context("the name is too long")?;
    let name = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: PWSTR(units.as_mut_ptr()),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root.unwrap_or_default(),
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: descriptor.map_or(std::ptr::null(), |sd| sd.0 as *const _),
        ..Default::default()
    };
    Ok(call(&attributes))
}

/// A security descriptor parsed from SDDL, freed on drop.
fn descriptor_from_sddl(sddl: &str) -> anyhow::Result<LocalSd> {
    let sddl_w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut psd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: a NUL-terminated string and a valid out-pointer; `LocalSd` frees what it returns.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl_w.as_ptr()), SDDL_REVISION_1, &mut psd, None)
    }
    .context("parse a security descriptor")?;
    Ok(LocalSd(psd))
}

/// Needs `FILE_READ_ATTRIBUTES` on `handle`.
fn file_information(handle: HANDLE) -> anyhow::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: a valid handle and an out-pointer to a local.
    unsafe { GetFileInformationByHandle(handle, &mut info) }.context("read the attributes")?;
    Ok(info)
}

fn file_attributes(handle: HANDLE) -> anyhow::Result<u32> {
    Ok(file_information(handle)?.dwFileAttributes)
}

fn status_error(status: NTSTATUS) -> windows::core::Error {
    // SAFETY: a pure conversion of a status code.
    windows::core::Error::from(HRESULT::from_win32(unsafe { RtlNtStatusToDosError(status) }))
}

/// What the status of an [`nt_create`] means: the one place a status becomes an outcome.
#[derive(Debug, PartialEq, Eq)]
enum OpenOutcome {
    Opened,
    /// The object refuses even the rights asked for; for an inspection, not an error of it.
    Denied,
    /// Nothing is at the name, or at a name on the way to it.
    Missing,
    /// A file is at the name of a directory that was asked for.
    NotADirectory,
    Failed(NTSTATUS),
}

fn classify_open(status: NTSTATUS) -> OpenOutcome {
    if status.0 >= 0 {
        OpenOutcome::Opened
    } else if status == STATUS_ACCESS_DENIED {
        OpenOutcome::Denied
    } else if status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND {
        OpenOutcome::Missing
    } else if status == STATUS_NOT_A_DIRECTORY {
        OpenOutcome::NotADirectory
    } else {
        OpenOutcome::Failed(status)
    }
}

/// `dir` as an NT object-manager path (`\??\C:\...`), UTF-16 without a terminator.
fn nt_path(dir: &Path) -> anyhow::Result<Vec<u16>> {
    let abs: Vec<u16> = std::path::absolute(dir)
        .with_context(|| format!("make {} absolute", dir.display()))?
        .as_os_str()
        .encode_wide()
        .collect();
    let units = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
    // Longest prefix first: `\\?\UNC\` and `\\server` are both UNC, `\\?\` and `\\.\` are
    // device paths, and everything else is a drive path.
    let forms = [
        (r"\\?\UNC\", r"\??\UNC\"),
        (r"\\?\", r"\??\"),
        (r"\\.\", r"\??\"),
        (r"\\", r"\??\UNC\"),
    ];
    let (prefix, rest) = forms
        .iter()
        .find_map(|(win32, nt)| abs.strip_prefix(units(win32).as_slice()).map(|rest| (*nt, rest)))
        .unwrap_or((r"\??\", &abs[..]));
    Ok([units(prefix).as_slice(), rest].concat())
}

/// What the sentence of a refusal of an owner or an ACL says. Naming an account is a lookup that can
/// block, so these are built only for an object that is refused (see [`owner_acl_problem`]).
struct OwnerAclWords {
    /// The owner as the object has it.
    owner: String,
    /// The owners that would do.
    owner_set: String,
    /// What its ACL must be.
    acl_is: String,
}

/// Which of the owner and the ACL of a folder or file is wrong, or `None` if neither: the one
/// sentence every refusal of such an object is built from. `words` is called only when there is a
/// refusal.
fn owner_acl_problem(owner_ok: bool, acl_ok: bool, words: impl FnOnce() -> OwnerAclWords) -> Option<String> {
    if owner_ok && acl_ok {
        return None;
    }
    let OwnerAclWords {
        owner,
        owner_set,
        acl_is,
    } = words();
    Some(match (owner_ok, acl_ok) {
        (false, true) => format!("its owner is {owner}, not {owner_set}"),
        (true, false) => format!("its ACL is not {acl_is} (its owner, {owner}, is fine)"),
        _ => format!("its owner is {owner}, not {owner_set}, and its ACL is not {acl_is}"),
    })
}

/// The sentence for an object whose ACL this process may not read, so that it cannot be shown to be
/// `shown_to_be`.
fn denied_problem(shown_to_be: &str) -> String {
    format!("this process is denied access to read its ACL, so it cannot be shown to be {shown_to_be}")
}

/// The ACEs of [`INSTALL_DIR_SDDL`], as [`Security::dacl_matches`] takes them.
fn install_grants<'a>(system: &'a Sid, admins: &'a Sid, users: &'a Sid) -> [Grant<'a>; 3] {
    let grant = |sid, mask| Grant {
        sid,
        mask,
        flags: Some(INSTALL_ACE_FLAGS),
    };
    [
        grant(system, FILE_ALL_ACCESS.0),
        grant(admins, FILE_ALL_ACCESS.0),
        grant(users, FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0),
    ]
}

/// Why `dir` is not an install directory this build made, or `None` if it is one.
pub fn install_dir_problem(dir: &Path) -> anyhow::Result<Option<String>> {
    problem_from_open(dir, open_for_inspection(dir)?)
}

/// [`install_dir_problem`] given the outcome of opening `dir` for inspection: `None` means the
/// open was denied.
fn problem_from_open(dir: &Path, handle: Option<OwnedHandle>) -> anyhow::Result<Option<String>> {
    let Some(handle) = handle else {
        return Ok(Some(denied_problem("the hardened one")));
    };

    let security = Security::from_handle(handle.0).with_context(|| format!("read the ACL of {}", dir.display()))?;

    let attributes = file_attributes(handle.0).with_context(|| format!("read the attributes of {}", dir.display()))?;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Ok(Some(format!(
            "it is a reparse point (junction or symlink); owner {}",
            describe_sid(security.owner)
        )));
    }
    if attributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0 {
        return Ok(Some(format!(
            "it is not a directory; owner {}",
            describe_sid(security.owner)
        )));
    }

    let system = Sid::well_known(WellKnown::System)?;
    let admins = Sid::well_known(WellKnown::Administrators)?;
    let users = Sid::well_known(WellKnown::Users)?;
    let grants = install_grants(&system, &admins, &users);
    // `INSTALL_DIR_SDDL` makes Administrators the owner, so nothing else is accepted.
    let owner_ok = security.owner_in(&[&admins])?;
    let acl_ok = security.dacl_matches(&grants)?;
    Ok(owner_acl_problem(owner_ok, acl_ok, || OwnerAclWords {
        owner: describe_sid(security.owner),
        owner_set: "the Administrators group".into(),
        acl_is: "the hardened one".into(),
    }))
}

/// Create `dir` with the install-directory DACL, or accept it if this build made it already.
///
/// `dir`'s parent must exist. If `dir` exists (including losing a creation race to another
/// caller) it must verify under [`verify_install_dir_acl`] and not be a reparse point; an
/// existing directory that does not is an error naming it, its owner and the fix, and is never
/// modified: it may have been made by anyone.
pub fn ensure_install_dir(dir: &Path) -> anyhow::Result<()> {
    create_install_dir(dir)?;
    if let Some(problem) = install_dir_problem(dir)? {
        anyhow::bail!(
            "the install directory {} exists but cannot be trusted: {problem}. \
             Inspect it, remove it, and run `apply` again",
            dir.display()
        );
    }
    Ok(())
}

/// `CreateDirectoryW` with [`INSTALL_DIR_SDDL`]. "Already exists" is not an error here: the
/// caller decides whether what exists is acceptable.
fn create_install_dir(dir: &Path) -> anyhow::Result<()> {
    let sd = descriptor_from_sddl(INSTALL_DIR_SDDL)?;
    let path_w = wide(dir);
    unsafe {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0.0,
            bInheritHandle: BOOL(0),
        };
        match CreateDirectoryW(PCWSTR(path_w.as_ptr()), Some(&attributes)) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == HRESULT::from_win32(ERROR_ALREADY_EXISTS.0) => Ok(()),
            Err(e) => Err(anyhow::Error::new(e).context(format!(
                "create the install directory {} (this needs an elevated administrator)",
                dir.display()
            ))),
        }
    }
}

/// `true` iff `dir` is exactly the [`INSTALL_DIR_SDDL`] policy and not a reparse point. Anything
/// unexpected is `false`: fail-closed.
pub fn verify_install_dir_acl(dir: &Path) -> anyhow::Result<bool> {
    Ok(install_dir_problem(dir)?.is_none())
}

/// `true` iff `sid` is one of `set`.
fn is_in(sid: &Sid, set: &[&Sid]) -> bool {
    // SAFETY: `Sid` holds a copy of SID bytes; validity is checked before EqualSid.
    unsafe { IsValidSid(sid.as_psid()).as_bool() && set.iter().any(|s| EqualSid(sid.as_psid(), s.as_psid()).is_ok()) }
}

#[cfg(test)]
#[path = "acl_tests.rs"]
mod acl_tests;
