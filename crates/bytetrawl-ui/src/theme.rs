//! ByteTrawl's semantic color tokens.
//!
//! The dark palette is derived from xnu.app's warm terminal theme. Keeping
//! these as semantic tokens prevents individual inspectors from inventing
//! their own colors and leaves room for additional appearance modes.

pub const BACKGROUND: u32 = 0x0e0d0b;
pub const PANEL: u32 = 0x141310;
pub const PANEL_RAISED: u32 = 0x1c1b17;
pub const BORDER: u32 = 0x25231e;
pub const TEXT: u32 = 0xd7d3c6;
pub const TEXT_MUTED: u32 = 0x978f7d;
pub const PRIMARY: u32 = 0x9acf68;
pub const ACCENT: u32 = 0xd69b51;
pub const DESTRUCTIVE: u32 = 0xd86d5f;
pub const SELECTION: u32 = 0x293326;
pub const WARNING: u32 = 0xd69b51;
pub const HIGH: u32 = 0xdf805d;
pub const PRIMARY_HOVER: u32 = 0xaddb7f;
pub const PRIMARY_ACTIVE: u32 = 0x83b655;
pub const DESTRUCTIVE_HOVER: u32 = 0xe18478;
pub const DESTRUCTIVE_ACTIVE: u32 = 0xbd594d;
