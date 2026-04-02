// SPDX-License-Identifier: MIT
//! Binary format parsing for Arq5 and Arq7 on-disk structures.

pub mod arq5;
pub mod arq5_adapter;
pub mod arq7;
pub mod backup_record;
mod primitives;

#[allow(unused_imports)]
pub use arq5::{
    Arq5BlobKey, Arq5Commit, Arq5Node, Arq5Tree, PackIndex, PackIndexDb, PackObject,
    parse_pack_file,
};
pub use arq7::BackupRecord;
pub use backup_record::{list_all_backup_folders, read_arq5_computer_info, read_backup_config};
