//! Concrete hash types.
//!
//! The v0 reference slice is [`Md5`] and [`SaltedMd5`].

mod md5;
mod salted_md5;

pub use md5::Md5;
pub use salted_md5::SaltedMd5;
