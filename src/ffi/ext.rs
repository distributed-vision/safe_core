use core::client::Client;
use ffi::FfiHandle;
use std::sync::{Arc, Mutex};

/// dv Ffi extenstions
pub struct FfiExt {
}

impl FfiExt {
    /// Get ffi handle from client
    pub fn cast_to_ffi_handle(client: Client) -> *mut FfiHandle {
        //return ffi::cast_to_ffi_handle(client);
        let ffi_handle = Box::new(FfiHandle {
            client: Arc::new(Mutex::new(client)),
            network_thread_terminator: None,
            raii_joiner: None,
            network_event_observers: Arc::new(Mutex::new(Vec::with_capacity(3))),
        });
        Box::into_raw(ffi_handle)
    }
}
