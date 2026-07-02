//! Float math shims routed through `libm`.
//!
//! Core passes need `ln`/`log2` (Shannon entropy) and `abs` (confidence
//! blending). These are inherent `f32` methods only with `std`, and platform
//! libm implementations vary in the last ulp. Routing every profile through
//! the pure-Rust `libm` crate keeps entropy scores bit-identical across
//! std / no_std / wasm builds and lets the core compile under no_std + alloc.

#[inline]
pub(crate) fn ln(x: f32) -> f32 {
    libm::logf(x)
}

#[inline]
pub(crate) fn log2(x: f32) -> f32 {
    libm::log2f(x)
}

/// Bit-mask `abs` — works in core on all toolchains.
#[inline]
pub(crate) fn abs(x: f32) -> f32 {
    f32::from_bits(x.to_bits() & 0x7fff_ffff)
}
