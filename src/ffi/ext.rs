
use core::client::ext::ClientExt;
use std::sync::{Arc, Mutex};
use std::ops::Deref;
use super::errors::FfiError;
use super::helper;
use super::session::Session;
use super::launcher_config_handler::ConfigHandler;
use super::app::App;

/// dv Ffi session extenstions
pub struct SessionExt {
}

impl SessionExt {

    /// Create new account.
    pub fn create_account(keyword: &Vec<u8>, pin: &Vec<u8>, password: &Vec<u8>) -> Result<Session, FfiError> {
        let client = try!(ClientExt::create_account(
                keyword, pin, password));
        let client = Arc::new(Mutex::new(client));

        let safe_drive_dir_key = try!(helper::get_safe_drive_key(client.clone()));

        Ok(Session::new(
            client,
            Some(safe_drive_dir_key),
            Default::default(),
            None))
    }

    /// Log in to existing account.
    pub fn log_in(keyword: &Vec<u8>, pin: &Vec<u8>, password: &Vec<u8>) -> Result<Session, FfiError> {
        let client = try!(ClientExt::log_in(
            keyword, pin, password));
        let client = Arc::new(Mutex::new(client));

        let safe_drive_dir_key = try!(helper::get_safe_drive_key(client.clone()));

        Ok(Session::new(
            client,
            Some(safe_drive_dir_key),
            Default::default(),
            None))
    }

    /// Return the session network identity
    pub fn get_session_network_id( session: &Session ) -> Vec<u8> {
        let client = session.get_client();
        let network_id=ClientExt::get_network_id(unwrap!(client.lock()).deref());
        network_id
    }

}

/// dv Ffi app extenstions
pub struct AppExt {
}

impl AppExt {
    /// Return the application config identity
    pub fn generate_app_id( session: &Session, app_id: &str, vendor: &str ) -> Vec<u8> {
        let client = session.get_client();
        let handler = ConfigHandler::new(client);
		let app_id = handler.get_app_id(&app_id, &vendor);
        app_id[..].to_vec()
    }

    /// Return the app config identity associated with this app
    pub fn get_app_id(app: &App) -> Result<Vec<u8>, FfiError> {
        let client = app.get_client();
        let handler = ConfigHandler::new(client);
        if let Some(ref app_dir_key) = app.get_app_dir_key() {
            let app_id=try!(handler.get_app_id_for_key(app_dir_key));
            return Ok(app_id[..].to_vec());
        }
        Err(FfiError::PathNotFound)
    }
}
