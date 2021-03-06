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

//! Operations on file writer


use core::SelfEncryptionStorage;
use ffi::app::App;
use ffi::errors::FfiError;
use ffi::helper;
use libc::int32_t;
use nfs::errors::NfsError;
use nfs::file::File;
use nfs::helper::writer::Mode;
use nfs::helper::writer::Writer as InnerWriter;
use nfs::metadata::file_metadata::FileMetadata;
use rustc_serialize::base64::FromBase64;
use self_encryption::DataMap;
use std::mem;
use std::slice;

/// File writer.
pub struct Writer {
    inner: InnerWriter<'static>,
    app: *const App,
    file_path: String,
    is_path_shared: bool,
    _storage: Box<SelfEncryptionStorage>,
}

impl Writer {
    fn close(self) -> Result<(), FfiError> {
        let _ = try!(self.inner.close());
        Ok(())
    }
}

/// Create new file and return a NFS Writer handle to it.
#[no_mangle]
pub unsafe extern "C" fn nfs_create_file(app_handle: *const App,
                                         file_path: *const u8,
                                         file_path_len: usize,
                                         user_metadata: *const u8,
                                         user_metadata_len: usize,
                                         is_path_shared: bool,
                                         writer_handle: *mut *mut Writer)
                                         -> int32_t {
    helper::catch_unwind_i32(|| {
        trace!("FFI get nfs writer for creating a new file.");

        let file_path = ffi_try!(helper::c_utf8_to_str(file_path, file_path_len));
        let user_metadata = ffi_try!(helper::c_utf8_to_str(user_metadata, user_metadata_len));

        let writer = ffi_try!(create_file(&*app_handle, file_path, user_metadata, is_path_shared));

        *writer_handle = Box::into_raw(Box::new(writer));
        0
    })
}

/// Obtain NFS writer handle for writing data to a file in streaming mode
#[no_mangle]
pub unsafe extern "C" fn nfs_writer_open(app_handle: *const App,
                                         file_path: *const u8,
                                         file_path_len: usize,
                                         is_path_shared: bool,
                                         writer_handle: *mut *mut Writer)
                                         -> int32_t {
    helper::catch_unwind_i32(|| {
        trace!("FFI get nfs writer for modification of existing file.");
        let file_path = ffi_try!(helper::c_utf8_to_str(file_path, file_path_len));
        let writer = ffi_try!(writer_open(&*app_handle, file_path, is_path_shared));
        *writer_handle = Box::into_raw(Box::new(writer));
        0
    })
}

/// Write data to the Network using the NFS Writer handle
#[no_mangle]
pub unsafe extern "C" fn nfs_writer_write(writer_handle: *mut Writer,
                                          data: *const u8,
                                          len: usize)
                                          -> int32_t {
    helper::catch_unwind_i32(|| {
        trace!("FFI Write data using nfs writer.");

        let data = slice::from_raw_parts(data, len);
        ffi_try!((*writer_handle).inner.write(&data[..]));
        0
    })
}

/// Closes the NFS Writer handle
#[no_mangle]
pub unsafe extern "C" fn nfs_writer_close(writer_handle: *mut Writer) -> int32_t {
    helper::catch_unwind_i32(|| {
        trace!("FFI Close and consume nfs writer.");
        let writer = *Box::from_raw(writer_handle);
        ffi_try!(writer.close());
        0
    })
}

/// Sync the NFS Writer handle
#[no_mangle]
pub unsafe extern "C" fn nfs_writer_sync( handle_to_sync: *mut Writer,
                                              synced_handle: *mut *mut Writer) -> int32_t {
    helper::catch_unwind_i32(|| {
        trace!("FFI syncronize existing writer and return a new one at same position.");

        let to_sync = *Box::from_raw(handle_to_sync);

        let app = to_sync.app;
        let file_path = to_sync.file_path.to_string();
        let is_path_shared = to_sync.is_path_shared;

        ffi_try!(to_sync.close());
        let synced = ffi_try!(writer_open(app, &file_path, is_path_shared));

        *synced_handle = Box::into_raw(Box::new(synced));
        0
    })
}

#[allow(unsafe_code)]
unsafe fn create_file(app_handle: *const App,
               file_path: &str,
               user_metadata: &str,
               is_path_shared: bool)
               -> Result<Writer, FfiError> {
    let app=&*app_handle;
    let (directory, file_name) =
        try!(helper::get_directory_and_file(app, file_path, is_path_shared));

    let user_metadata = try!(parse_result!(user_metadata.from_base64(),
                                           "Failed Converting from Base64."));

    let mut storage = Box::new(SelfEncryptionStorage::new(app.get_client()));

    let inner: InnerWriter<'static> = {
        let inner = match directory.find_file(&file_name) {
            Some(_) => try!(Err(NfsError::FileAlreadyExistsWithSameName)),
            None => {
                let file = try!(File::new(FileMetadata::new(file_name, user_metadata),
                                          DataMap::None));
                try!(InnerWriter::new(app.get_client(),
                                      &mut *storage,
                                      Mode::Overwrite,
                                      directory,
                                      file))
            }
        };

        { mem::transmute(inner) }
    };

    Ok(Writer {
        inner: inner,
        app: app_handle,
        is_path_shared: is_path_shared,
        file_path: file_path.to_string(),
        _storage: storage,
    })
}

unsafe fn writer_open(app_handle: *const App, file_path: &str, is_path_shared: bool) -> Result<Writer, FfiError> {
    let app=&*app_handle;
    let (directory, file_name) =
        try!(helper::get_directory_and_file(app, file_path, is_path_shared));

    let file = try!(directory.find_file(&file_name).cloned().ok_or(FfiError::InvalidPath));
    let mut storage = Box::new(SelfEncryptionStorage::new(app.get_client()));

    let inner: InnerWriter<'static> = {
        let inner = try!(InnerWriter::new(app.get_client(),
                                          &mut *storage,
                                          Mode::Modify,
                                          directory,
                                          file));

        { mem::transmute(inner) }
    };

    Ok(Writer {
        inner: inner,
        app: app_handle,
        is_path_shared: is_path_shared,
        file_path: file_path.to_string(),
        _storage: storage,
    })
}

#[cfg(test)]
mod test {

    use ffi::test_utils;
    use nfs::helper::directory_helper::DirectoryHelper;
    use nfs::helper::file_helper::FileHelper;
    use std::str;

    #[test]
    fn create_file() {
        const METADATA_BASE64: &'static str = "c2FtcGxlIHRleHQ=";

        let app = test_utils::create_app(false);
        let dir_helper = DirectoryHelper::new(app.get_client());
        let mut file_helper = FileHelper::new(app.get_client());

        let mut writer =
            unwrap!(super::create_file(&app, "/test_file.txt", METADATA_BASE64, false));
        unwrap!(writer.inner.write("hello world".as_bytes()));
        let _ = unwrap!(writer.close());

        let app_dir_key = unwrap!(app.get_app_dir_key());
        let app_dir = unwrap!(dir_helper.get(&app_dir_key));

        let file = unwrap!(app_dir.find_file("test_file.txt"));
        let mut reader = unwrap!(file_helper.read(file));
        let size = reader.size();

        let content = unwrap!(reader.read(0, size));
        let content = unwrap!(str::from_utf8(&content));
        assert_eq!(content, "hello world");
    }
}
