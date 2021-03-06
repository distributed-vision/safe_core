// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use ffi::errors::FfiError;
use ffi::helper;
use ffi::low_level_api::{AppendableDataHandle, DataIdHandle, EncryptKeyHandle, SignKeyHandle,
                         StructDataHandle};
use ffi::low_level_api::appendable_data::AppendableData;
use ffi::low_level_api::object_cache::object_cache;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use std::{mem, ptr, slice};

/// Free Encrypt Key handle
#[no_mangle]
pub extern "C" fn misc_encrypt_key_free(handle: EncryptKeyHandle) -> i32 {
    helper::catch_unwind_i32(|| {
        let _ = ffi_try!(unwrap!(object_cache()).remove_encrypt_key(handle));
        0
    })
}

/// Free Sign Key handle
#[no_mangle]
pub extern "C" fn misc_sign_key_free(handle: SignKeyHandle) -> i32 {
    helper::catch_unwind_i32(|| {
        let _ = ffi_try!(unwrap!(object_cache()).remove_sign_key(handle));
        0
    })
}

/// Serialise DataIdentifier
#[no_mangle]
pub unsafe extern "C" fn misc_serialise_data_id(data_id_h: DataIdHandle,
                                                o_data: *mut *mut u8,
                                                o_size: *mut usize,
                                                o_capacity: *mut usize)
                                                -> i32 {
    helper::catch_unwind_i32(|| {
        let mut ser_data_id = ffi_try!(serialise(ffi_try!(unwrap!(object_cache())
                .get_data_id(data_id_h)))
            .map_err(FfiError::from));

        *o_data = ser_data_id.as_mut_ptr();
        ptr::write(o_size, ser_data_id.len());
        ptr::write(o_capacity, ser_data_id.capacity());
        mem::forget(ser_data_id);

        0
    })
}

/// Deserialise DataIdentifier
#[no_mangle]
pub unsafe extern "C" fn misc_deserialise_data_id(data: *const u8,
                                                  size: usize,
                                                  o_handle: *mut DataIdHandle)
                                                  -> i32 {
    helper::catch_unwind_i32(|| {
        let ser_data_id = slice::from_raw_parts(data, size);
        let data_id = ffi_try!(deserialise(ser_data_id).map_err(FfiError::from));

        let handle = unwrap!(object_cache()).insert_data_id(data_id);
        ptr::write(o_handle, handle);

        0
    })
}

/// Serialise AppendableData
#[no_mangle]
pub unsafe extern "C" fn misc_serialise_appendable_data(ad_h: AppendableDataHandle,
                                                        o_data: *mut *mut u8,
                                                        o_size: *mut usize,
                                                        o_capacity: *mut usize)
                                                        -> i32 {
    helper::catch_unwind_i32(|| {
        let mut object_cache = unwrap!(object_cache());
        let mut ser_ad = match *ffi_try!(object_cache.get_ad(ad_h)) {
            AppendableData::Pub(ref ad) => ffi_try!(serialise(ad).map_err(FfiError::from)),
            AppendableData::Priv(ref ad) => ffi_try!(serialise(ad).map_err(FfiError::from)),
        };

        *o_data = ser_ad.as_mut_ptr();
        ptr::write(o_size, ser_ad.len());
        ptr::write(o_capacity, ser_ad.capacity());
        mem::forget(ser_ad);

        0
    })
}

/// Deserialise AppendableData
#[no_mangle]
pub unsafe extern "C" fn misc_deserialise_appendable_data(data: *const u8,
                                                          size: usize,
                                                          o_handle: *mut AppendableDataHandle)
                                                          -> i32 {
    helper::catch_unwind_i32(|| {
        let ser_ad = slice::from_raw_parts(data, size);
        let ad = {
            if let Ok(elt) = deserialise(ser_ad) {
                AppendableData::Priv(elt)
            } else {
                AppendableData::Pub(ffi_try!(deserialise(ser_ad).map_err(FfiError::from)))
            }
        };

        let handle = unwrap!(object_cache()).insert_ad(ad);
        ptr::write(o_handle, handle);

        0
    })
}

/// Serialise StructuredData
#[no_mangle]
pub unsafe extern "C" fn misc_serialise_struct_data(sd_h: StructDataHandle,
                                                    o_data: *mut *mut u8,
                                                    o_size: *mut usize,
                                                    o_capacity: *mut usize)
                                                    -> i32 {
    helper::catch_unwind_i32(|| {
        let mut ser_ad = ffi_try!(serialise(ffi_try!(unwrap!(object_cache()).get_sd(sd_h)))
            .map_err(FfiError::from));

        *o_data = ser_ad.as_mut_ptr();
        ptr::write(o_size, ser_ad.len());
        ptr::write(o_capacity, ser_ad.capacity());
        mem::forget(ser_ad);

        0
    })
}

/// Deserialise StructuredData
#[no_mangle]
pub unsafe extern "C" fn misc_deserialise_struct_data(data: *const u8,
                                                      size: usize,
                                                      o_handle: *mut StructDataHandle)
                                                      -> i32 {
    helper::catch_unwind_i32(|| {
        let ser_sd = slice::from_raw_parts(data, size);
        let sd = ffi_try!(deserialise(ser_sd).map_err(FfiError::from));

        let handle = unwrap!(object_cache()).insert_sd(sd);
        ptr::write(o_handle, handle);

        0
    })
}

/// Deallocate pointer obtained via FFI and allocated by safe_core
#[no_mangle]
pub unsafe extern "C" fn misc_u8_ptr_free(ptr: *mut u8, size: usize, capacity: usize) {
    // TODO: refactor implementation to remove the need for `cap`. Related issue:
    // <https://github.com/rust-lang/rust/issues/36284>.
    let _ = Vec::from_raw_parts(ptr, size, capacity);
}

/// Reset the object cache (drop all objects stored in it). This will invalidate
/// all currently held object handles.
pub extern "C" fn misc_object_cache_reset() {
    unwrap!(object_cache()).reset()
}

#[cfg(test)]
mod tests {
    use ffi::low_level_api::data_id::*;
    use ffi::low_level_api::object_cache::object_cache;
    use rand;
    use routing::DataIdentifier;
    use std::ptr;
    use super::*;

    #[test]
    fn data_id_serialisation() {
        let data_id_sd = DataIdentifier::Structured(rand::random(), rand::random());
        let data_id_id = DataIdentifier::Immutable(rand::random());
        let data_id_ad = DataIdentifier::PrivAppendable(rand::random());
        assert!(data_id_sd != data_id_id);
        assert!(data_id_sd != data_id_ad);
        assert!(data_id_ad != data_id_id);

        let (sd_data_id_h, id_data_id_h, ad_data_id_h) = {
            let mut object_cache = unwrap!(object_cache());

            (object_cache.insert_data_id(data_id_sd),
             object_cache.insert_data_id(data_id_id),
             object_cache.insert_data_id(data_id_ad))
        };

        unsafe {
            let mut data_ptr: *mut u8 = ptr::null_mut();
            let mut data_size = 0;
            let mut capacity = 0;
            assert_eq!(misc_serialise_data_id(sd_data_id_h,
                                              &mut data_ptr,
                                              &mut data_size,
                                              &mut capacity),
                       0);

            let mut data_id_h = 0;
            assert_eq!(misc_deserialise_data_id(data_ptr, data_size, &mut data_id_h),
                       0);
            assert!(data_id_h != sd_data_id_h);

            {
                let mut object_cache = unwrap!(object_cache());
                let before_id = *unwrap!(object_cache.get_data_id(sd_data_id_h));
                let after_id = unwrap!(object_cache.get_data_id(data_id_h));

                assert_eq!(before_id, *after_id);
                assert_eq!(data_id_sd, *after_id);
            }

            assert_eq!(data_id_free(data_id_h), 0);
            misc_u8_ptr_free(data_ptr, data_size, capacity);
        }

        unsafe {
            let mut data_ptr: *mut u8 = ptr::null_mut();
            let mut data_size = 0;
            let mut capacity = 0;
            assert_eq!(misc_serialise_data_id(id_data_id_h,
                                              &mut data_ptr,
                                              &mut data_size,
                                              &mut capacity),
                       0);

            let mut data_id_h = 0;
            assert_eq!(misc_deserialise_data_id(data_ptr, data_size, &mut data_id_h),
                       0);
            assert!(data_id_h != id_data_id_h);

            {
                let mut object_cache = unwrap!(object_cache());
                let before_id = *unwrap!(object_cache.get_data_id(id_data_id_h));
                let after_id = unwrap!(object_cache.get_data_id(data_id_h));

                assert_eq!(before_id, *after_id);
                assert_eq!(data_id_id, *after_id);
            }

            assert_eq!(data_id_free(data_id_h), 0);
            misc_u8_ptr_free(data_ptr, data_size, capacity);
        }

        unsafe {
            let mut data_ptr: *mut u8 = ptr::null_mut();
            let mut data_size = 0;
            let mut capacity = 0;
            assert_eq!(misc_serialise_data_id(ad_data_id_h,
                                              &mut data_ptr,
                                              &mut data_size,
                                              &mut capacity),
                       0);

            let mut data_id_h = 0;
            assert_eq!(misc_deserialise_data_id(data_ptr, data_size, &mut data_id_h),
                       0);
            assert!(data_id_h != ad_data_id_h);

            {
                let mut object_cache = unwrap!(object_cache());
                let before_id = *unwrap!(object_cache.get_data_id(ad_data_id_h));
                let after_id = unwrap!(object_cache.get_data_id(data_id_h));

                assert_eq!(before_id, *after_id);
                assert_eq!(data_id_ad, *after_id);
            }

            assert_eq!(data_id_free(data_id_h), 0);
            misc_u8_ptr_free(data_ptr, data_size, capacity);
        }

        assert_eq!(data_id_free(sd_data_id_h), 0);
        assert_eq!(data_id_free(id_data_id_h), 0);
        assert_eq!(data_id_free(ad_data_id_h), 0);
    }
}
