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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{Sender, Receiver};

use core::errors::CoreError;
use core::translated_events::{NetworkEvent, ResponseEvent};

use xor_name::XorName;
use lru_time_cache::LruCache;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use routing::{MessageId, Data, Event, ResponseContent, RequestMessage, RequestContent};

const EVENT_RECEIVER_THREAD_NAME: &'static str = "EventReceiverThread";

/// MessageQueue gets and collects messages/responses from routing. It also maintains local caching
/// of previously fetched ImmutableData (because the very nature of such data implies Immutability)
/// enabling fast re-retrieval and avoiding networking.
pub struct MessageQueue {
    local_cache: LruCache<XorName, Data>,
    network_event_observers: Vec<Sender<NetworkEvent>>,
    response_observers: HashMap<MessageId, Sender<ResponseEvent>>,
}

impl MessageQueue {
    /// Create a new instance of MessageQueue. `data_senders` can be added later via function to
    /// add observer since one will not receive data until one asks for it. Thus there is enough
    /// chance to add an observer before requesting data.
    pub fn new(routing_event_receiver: Receiver<Event>,
               network_event_observers: Vec<Sender<NetworkEvent>>)
               -> (Arc<Mutex<MessageQueue>>, RaiiThreadJoiner) {
        let message_queue = Arc::new(Mutex::new(MessageQueue {
            local_cache: LruCache::with_capacity(1000),
            network_event_observers: network_event_observers,
            response_observers: HashMap::new(),
        }));

        let message_queue_cloned = message_queue.clone();
        let receiver_joiner = thread!(EVENT_RECEIVER_THREAD_NAME, move || {
            for it in routing_event_receiver.iter() {
                match it {
                    Event::Response(msg) => {
                        match msg.content {
                            ResponseContent::GetSuccess(data, msg_id) => {
                                let mut queue_guard = unwrap_result!(message_queue_cloned.lock());
                                if let Some(mut response_observer) =
                                       queue_guard.response_observers.remove(&msg_id) {
                                    let _ = response_observer.send(ResponseEvent::Get(Ok(data)));
                                }
                            }
                            ResponseContent::GetFailure {
                                id,
                                request: RequestMessage {
                                    content: RequestContent::Get(data_req, _),
                                    ..
                                },
                                ..
                            } => {
                                let mut queue_guard = unwrap_result!(message_queue_cloned.lock());
                                if let Some(mut response_observer) =
                                       queue_guard.response_observers.remove(&id) {
                                    let response =
                                        ResponseEvent::Get(Err(CoreError::GetFailure(data_req)));
                                    let _ = response_observer.send(response);
                                }
                            }
                            ResponseContent::PutSuccess(_, msg_id) => {
                                let mut queue_guard = unwrap_result!(message_queue_cloned.lock());
                                if let Some(mut response_observer) =
                                       queue_guard.response_observers.remove(&msg_id) {
                                    let _ =
                                        response_observer.send(ResponseEvent::MutationResp(Ok(())));
                                }
                            }
                            ResponseContent::PutFailure {
                                id,
                                request: RequestMessage {
                                    content: RequestContent::Put(data, _),
                                    ..
                                },
                                ..
                            } => {
                                let mut queue_guard = unwrap_result!(message_queue_cloned.lock());
                                if let Some(mut response_observer) =
                                       queue_guard.response_observers.remove(&id) {
                                    let response =
                                        ResponseEvent::MutationResp(Err(CoreError::MutationFailure(data)));
                                    let _ = response_observer.send(response);
                                }
                            }
                            ResponseContent::PostSuccess(_, msg_id) => {
                                let mut queue_guard = unwrap_result!(message_queue_cloned.lock());
                                if let Some(mut response_observer) =
                                       queue_guard.response_observers.remove(&msg_id) {
                                    let _ =
                                        response_observer.send(ResponseEvent::MutationResp(Ok(())));
                                }
                            }
                            ResponseContent::PostFailure {
                                id,
                                request: RequestMessage {
                                    content: RequestContent::Post(data, _),
                                    ..
                                },
                                ..
                            } => {
                                let mut queue_guard = unwrap_result!(message_queue_cloned.lock());
                                if let Some(mut response_observer) =
                                       queue_guard.response_observers.remove(&id) {
                                    let response =
                                        ResponseEvent::MutationResp(Err(CoreError::MutationFailure(data)));
                                    let _ = response_observer.send(response);
                                }
                            }
                            ResponseContent::DeleteSuccess(_, msg_id) => {
                                let mut queue_guard = unwrap_result!(message_queue_cloned.lock());
                                if let Some(mut response_observer) =
                                       queue_guard.response_observers.remove(&msg_id) {
                                    let _ =
                                        response_observer.send(ResponseEvent::MutationResp(Ok(())));
                                }
                            }
                            ResponseContent::DeleteFailure {
                                id,
                                request: RequestMessage {
                                    content: RequestContent::Delete(data, _),
                                    ..
                                },
                                ..
                            } => {
                                let mut queue_guard = unwrap_result!(message_queue_cloned.lock());
                                if let Some(mut response_observer) =
                                       queue_guard.response_observers.remove(&id) {
                                    let response =
                                        ResponseEvent::MutationResp(Err(CoreError::MutationFailure(data)));
                                    let _ = response_observer.send(response);
                                }
                            }
                            _ => {
                                warn!("Received Response Message: {:?} ;; This is currently not \
                                       supported.",
                                      msg)
                            }
                        }
                    }
                    Event::Connected => {
                        let mut dead_sender_positions = Vec::<usize>::new();
                        let mut queue_guard = unwrap_result!(message_queue_cloned.lock());
                        for it in queue_guard.network_event_observers.iter().enumerate() {
                            if it.1.send(NetworkEvent::Connected).is_err() {
                                dead_sender_positions.push(it.0);
                            }
                        }

                        MessageQueue::purge_dead_senders(&mut queue_guard.network_event_observers,
                                                         dead_sender_positions);
                    }
                    Event::Disconnected => {
                        let mut dead_sender_positions = Vec::<usize>::new();
                        let mut queue_guard = unwrap_result!(message_queue_cloned.lock());
                        for it in queue_guard.network_event_observers.iter().enumerate() {
                            if it.1.send(NetworkEvent::Disconnected).is_err() {
                                dead_sender_positions.push(it.0);
                            }
                        }

                        MessageQueue::purge_dead_senders(&mut queue_guard.network_event_observers,
                                                         dead_sender_positions);
                    }
                    _ => {
                        debug!("Received Routing Event: {:?} ;; This is currently not supported.",
                               it)
                    }
                }
            }
        });

        (message_queue, RaiiThreadJoiner::new(receiver_joiner))
    }

    pub fn register_response_observer(&mut self,
                                      msg_id: MessageId,
                                      sender: Sender<ResponseEvent>) {
        let _ = self.response_observers.insert(msg_id, sender);
    }

    pub fn add_network_event_observer(&mut self, sender: Sender<NetworkEvent>) {
        self.network_event_observers.push(sender);
    }

    pub fn local_cache_check(&mut self, key: &XorName) -> bool {
        self.local_cache.contains_key(key)
    }

    pub fn local_cache_get(&mut self, key: &XorName) -> Result<Data, CoreError> {
        self.local_cache.get(key).ok_or(CoreError::VersionCacheMiss).map(|elt| elt.clone())
    }

    pub fn local_cache_insert(&mut self, key: XorName, value: Data) {
        let _ = self.local_cache.insert(key, value);
    }

    fn purge_dead_senders<T>(senders: &mut Vec<Sender<T>>, positions: Vec<usize>) {
        let mut delta = 0;
        for val in positions {
            let _ = senders.remove(val - delta);
            delta += 1;
        }
    }
}
