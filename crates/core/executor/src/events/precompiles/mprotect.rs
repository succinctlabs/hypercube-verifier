use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};

use crate::events::PageProtLocalEvent;

/// Mprotect precompile event.
#[derive(Clone, Debug, Default, Serialize, Deserialize, DeepSizeOf)]
pub struct MProtectEvent {
    /// Address being protected (page-aligned).
    pub addr: u64,
    /// Local page prot access.
    pub local_page_prot_access: Vec<PageProtLocalEvent>,
}
