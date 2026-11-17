//! What names a file or folder whatever path reaches it.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx};

/// What names a file or folder whatever path it is reached by: the volume and its 128-bit id on it.
/// (The 64-bit index of `BY_HANDLE_FILE_INFORMATION` is not unique on ReFS.)
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FileId {
    volume: u64,
    file: [u8; 16],
}

impl FileId {
    /// The identity of what `handle` is open on. Needs `FILE_READ_ATTRIBUTES` and no other access.
    pub fn of_handle(handle: HANDLE) -> std::io::Result<FileId> {
        let mut info = FILE_ID_INFO::default();
        // SAFETY: the caller's handle is open for the call; `info` is the size the call is told.
        unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                (&raw mut info).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        }
        .map_err(std::io::Error::from)?;
        Ok(FileId {
            volume: info.VolumeSerialNumber,
            file: info.FileId.Identifier,
        })
    }
}
