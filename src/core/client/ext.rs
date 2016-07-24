
use std::sync::mpsc;

use core::client::message_queue::MessageQueue;
use core::client::Client;
use core::client::SessionPacketEncryptionKeys;
use core::client::user_account::Account;
use core::errors::CoreError;
use core::translated_events::NetworkEvent;
use safe_network_common::TYPE_TAG_SESSION_PACKET;
use routing::{Data, DataIdentifier, FullId, StructuredData,XorName};

#[cfg(feature = "use-mock-routing")]
use core::client::non_networking_test_framework::RoutingMock as Routing;
#[cfg(not(feature = "use-mock-routing"))]
use routing::Client as Routing;

use sodiumoxide::crypto::hash::sha256;


/// dv client extenstion methods
pub struct ClientExt {
}

impl ClientExt {
    /// create account using raw network credentials
    pub fn create_account(keyword: Vec<u8>, pin: Vec<u8>, password: Vec<u8>) -> Result<Client, CoreError> {

        let account_packet = Account::new(None, None);
        let id_packet = FullId::with_keys((account_packet.get_maid().public_keys().1,
                                           account_packet.get_maid().secret_keys().1.clone()),
                                          (account_packet.get_maid().public_keys().0,
                                           account_packet.get_maid().secret_keys().0.clone()));

        let (routing_sender, routing_receiver) = mpsc::channel();
        let (network_event_sender, network_event_receiver) = mpsc::channel();

        let (message_queue, raii_joiner) = MessageQueue::new(routing_receiver,
                                                             vec![network_event_sender]);
        let routing = try!(Routing::new(routing_sender, Some(id_packet)));

        match try!(network_event_receiver.recv()) {
            NetworkEvent::Connected => (),
            _ => return Err(CoreError::OperationAborted),
        }
        
        let hash_sign_key = sha256::hash(&(account_packet.get_maid().public_keys().0).0);
        let client_manager_addr = XorName(hash_sign_key.0);

        let mut client = Client {
            account: Some(account_packet),
            routing: routing,
            _raii_joiner: raii_joiner,
            message_queue: message_queue,
            session_packet_id: Some(try!(Account::generate_network_id(&keyword, &pin))),
            session_packet_keys: Some(SessionPacketEncryptionKeys::new(password, pin)),
            client_manager_addr: Some(client_manager_addr),
            issued_gets: 0,
            issued_puts: 0,
            issued_posts: 0,
            issued_deletes: 0,
        };

        {
            let account_version = {
                let account = unwrap!(client.account.as_ref());
                let session_packet_keys = unwrap!(client.session_packet_keys.as_ref());

                let session_packet_id = unwrap!(client.session_packet_id.as_ref());
                try!(StructuredData::new(TYPE_TAG_SESSION_PACKET,
                                         *session_packet_id,
                                         0,
                                         try!(account.encrypt(session_packet_keys.get_password(),
                                                              session_packet_keys.get_pin())),
                                         vec![account.get_public_maid().public_keys().0.clone()],
                                         Vec::new(),
                                         Some(&account.get_maid().secret_keys().0)))
            };

            try!(client.put_recover(Data::Structured(account_version), None));
        }

        Ok(client)
    }

    /// login using raw network credentials
    pub fn log_in(keyword: Vec<u8>, pin: Vec<u8>, password: Vec<u8>) -> Result<Client, CoreError> {

        let mut unregistered_client = try!(Client::create_unregistered_client());
        let user_id = try!(Account::generate_network_id(&keyword, &pin));

        let session_packet_request = DataIdentifier::Structured(user_id, TYPE_TAG_SESSION_PACKET);

        let resp_getter = try!(unregistered_client.get(session_packet_request, None));

        if let Data::Structured(session_packet) = try!(resp_getter.get()) {
            let decrypted_session_packet =
                try!(Account::decrypt(session_packet.get_data(), &password, &pin));
            let id_packet = FullId::with_keys((decrypted_session_packet.get_maid()
                                                  .public_keys()
                                                  .1,
                                               decrypted_session_packet.get_maid()
                                                  .secret_keys()
                                                  .1
                                                  .clone()),
                                              (decrypted_session_packet.get_maid()
                                                  .public_keys()
                                                  .0,
                                               decrypted_session_packet.get_maid()
                                                  .secret_keys()
                                                  .0
                                                  .clone()));

            let (routing_sender, routing_receiver) = mpsc::channel();
            let (network_event_sender, network_event_receiver) = mpsc::channel();

            let (message_queue, raii_joiner) = MessageQueue::new(routing_receiver,
                                                                 vec![network_event_sender]);
            let routing = try!(Routing::new(routing_sender, Some(id_packet)));

            match try!(network_event_receiver.recv()) {
                NetworkEvent::Connected => (),
                _ => return Err(CoreError::OperationAborted),
            }

            let hash_sign_key = sha256::hash(&(decrypted_session_packet.get_maid()
                    .public_keys()
                    .0)
                .0);
            let client_manager_addr = XorName(hash_sign_key.0);

            let client = Client {
                account: Some(decrypted_session_packet),
                routing: routing,
                _raii_joiner: raii_joiner,
                message_queue: message_queue,
                session_packet_id: Some(try!(Account::generate_network_id(&keyword, &pin))),
                session_packet_keys: Some(SessionPacketEncryptionKeys::new(password, pin)),
                client_manager_addr: Some(client_manager_addr),
                issued_gets: 0,
                issued_puts: 0,
                issued_posts: 0,
                issued_deletes: 0,
            };

            Ok(client)
        } else {
            Err(CoreError::ReceivedUnexpectedData)
        }
    }
}
