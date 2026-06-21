//! # CIDR Module
//!
//! IP address expansion and CIDR block parsing.

mod expander;
mod blackrock;

pub use expander::{expand_cidr, CidrExpander};
pub use blackrock::BlackRock;

