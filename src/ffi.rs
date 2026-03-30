#![allow(non_camel_case_types)]

pub type c_void = core::ffi::c_void;

#[cfg(all(target_arch = "wasm32", target_os = "unknown", target_env = ""))]
pub type c_char = core::ffi::c_char;

#[cfg(all(target_arch = "wasm32", target_os = "unknown", target_env = ""))]
pub type c_ulonglong = u64;

#[cfg(all(target_arch = "wasm32", target_os = "unknown", target_env = ""))]
pub type size_t = usize;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown", target_env = "")))]
pub use libc::{c_char, c_ulonglong, size_t};
