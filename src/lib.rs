//! Opinionated DPDK bindings.
//!
//! This is useful for a minimal UDP sender/receiver.

#[macro_export]
macro_rules! mbuf_slice(
    ($mbuf: expr, $offset: expr, $len: expr) => {
        std::slice::from_raw_parts_mut(
            ((*$mbuf).buf_addr as *mut u8)
            .offset((*$mbuf).data_off as isize + $offset as isize),
            $len,
        )
    }
);

macro_rules! static_assert(
    ($x: expr) => {
        #[allow(unknown_lints, eq_op)]
        const _: [(); 0 - !{
            const ASSERT: bool = $x;
            ASSERT
        } as usize] = [];
    }
);

// raw bindings
pub mod bindings;
pub mod utils;
// still-unsafe slightly higher-level interface than the one in `bindings`.
mod socket;
pub mod wrapper;

pub use socket::{BoundDpdkConn, DpdkConn, DpdkIoKernel, DpdkIoKernelHandle, Msg};
