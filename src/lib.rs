//! Opinionated DPDK bindings.

macro_rules! mbuf_slice(
    ($mbuf: expr, $offset: expr, $len: expr) => {
        std::slice::from_raw_parts_mut(
            ((*$mbuf).buf_addr as *mut u8)
            .offset((*$mbuf).data_off as isize + $offset as isize),
            $len,
        )
    }
);

// raw bindings
mod bindings;
mod utils;
// still-unsafe slightly higher-level interface than the one in `bindings`.
mod socket;
mod wrapper;

pub use socket::{DpdkConn, DpdkIoKernel, DpdkIoKernelHandle};
