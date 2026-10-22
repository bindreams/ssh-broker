//! layout: where `apply` puts things under the install directory, and the order it touches them.

use std::path::{Path, PathBuf};

use crate::acl::Sid;

/// The install directory and the paths derived from it.
pub struct Layout {
    pub base: PathBuf,
}

impl Layout {
    pub fn production() -> Layout {
        unimplemented!()
    }
    pub fn config_path(&self) -> PathBuf {
        unimplemented!()
    }
    pub fn canonical_exe(&self) -> PathBuf {
        unimplemented!()
    }
    pub fn socket_dir(&self) -> PathBuf {
        unimplemented!()
    }
    pub fn logs_dir(&self) -> PathBuf {
        unimplemented!()
    }
}

pub fn ensure_base(_layout: &Layout) -> anyhow::Result<()> {
    unimplemented!()
}

pub fn resolve_user(_layout: &Layout, _cli_user: Option<&str>, _current_user: Option<&str>) -> anyhow::Result<String> {
    unimplemented!()
}

pub fn populate(_layout: &Layout, _current_exe: &Path, _user: &str, _sid: &Sid) -> anyhow::Result<PathBuf> {
    unimplemented!()
}

#[cfg(test)]
#[path = "layout_tests.rs"]
mod layout_tests;
