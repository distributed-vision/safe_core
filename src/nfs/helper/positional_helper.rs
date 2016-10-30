// Copyright 2015 MaidSafe.net limited.
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

use core::SelfEncryptionStorage;

use core::client::Client;
use nfs::directory_listing::DirectoryListing;
use nfs::errors::NfsError;
use nfs::file::File;
use nfs::helper::positional_writer::{Mode, Writer};
use std::sync::{Arc, Mutex};

/// File provides helper functions to perform Operations on Files
pub struct PosHelper {
    client: Arc<Mutex<Client>>,
    storage: SelfEncryptionStorage,
}

impl PosHelper {
    /// Create a new FileHelper instance
    pub fn new(client: Arc<Mutex<Client>>) -> PosHelper {
        PosHelper {
            client: client.clone(),
            storage: SelfEncryptionStorage::new(client),
        }
    }

    /// Helper function to Update content of a file in a directory listing
    /// A writer object is returned, through which the data for the file
    /// can be written to the network
    /// The file is actually saved in the directory listing only after
    /// `writer.close()` is invoked
    pub fn update_content(&mut self,
                          file: File,
                          mode: Mode,
                          parent_directory: DirectoryListing)
                          -> Result<Writer, NfsError> {
        trace!("Updating content in file with name {}", file.get_name());

        {
            let existing_file = try!(parent_directory.find_file(file.get_name())
                .ok_or(NfsError::FileNotFound));
            if *existing_file != file {
                return Err(NfsError::FileDoesNotMatch);
            }
        }
        Ok(try!(Writer::new(self.client.clone(),
                            &mut self.storage,
                            mode,
                            parent_directory,
                            file)))
    }

}
