use crate::error::{Error, Result};
use crate::{event::Event, nip05::Nip05Name};
use nauthz_grpc::authorization_client::AuthorizationClient;
use nauthz_grpc::event::TagEntry;
use nauthz_grpc::relay_server::{Relay, RelayServer};
use nauthz_grpc::{Decision, Event as GrpcEvent, EventReply, EventRequest, BroadcastEventRequest, BroadcastEventResponse};
use tokio::sync::broadcast::Sender;
use tracing::{info, warn, debug};

use tonic::transport::Server;
use tonic::{Request, Status, Response};

pub mod nauthz_grpc {
    tonic::include_proto!("nauthz");
}

// A decision for the DB to act upon
pub trait AuthzDecision: Send + Sync {
    fn permitted(&self) -> bool;
    fn denied(&self) -> bool;
    fn message(&self) -> Option<String>;
}

impl AuthzDecision for EventReply {
    fn permitted(&self) -> bool {
        self.decision == Decision::Permit as i32
    }
    fn denied(&self) -> bool {
        self.decision == Decision::Deny as i32
    }
    fn message(&self) -> Option<String> {
        self.message.clone()
    }
}

// A connection to an event admission GRPC server
pub struct EventAuthzService {
    server_addr: String,
    conn: Option<AuthorizationClient<tonic::transport::Channel>>,
}

// conversion of Nip05Names into GRPC type
impl std::convert::From<Nip05Name> for nauthz_grpc::event_request::Nip05Name {
    fn from(value: Nip05Name) -> Self {
        nauthz_grpc::event_request::Nip05Name {
            local: value.local.clone(),
            domain: value.domain.clone(),
        }
    }
}

// conversion of event tags into gprc struct
fn tags_to_protobuf(tags: &Vec<Vec<String>>) -> Vec<TagEntry> {
    tags.iter()
        .map(|x| TagEntry { values: x.clone() })
        .collect()
}

impl EventAuthzService {
    pub async fn connect(server_addr: &str) -> EventAuthzService {
        let mut eas = EventAuthzService {
            server_addr: server_addr.to_string(),
            conn: None,
        };
        eas.ready_connection().await;
        eas
    }

    pub async fn ready_connection(self: &mut Self) {
        if self.conn.is_none() {
            let client = AuthorizationClient::connect(self.server_addr.to_string()).await;
            if let Err(ref msg) = client {
                warn!("could not connect to nostr authz GRPC server: {:?}", msg);
            } else {
                info!("connected to nostr authorization GRPC server");
            }
            self.conn = client.ok();
        }
    }

    pub async fn admit_event(
        self: &mut Self,
        event: &Event,
        ip: &str,
        origin: Option<String>,
        user_agent: Option<String>,
        nip05: Option<Nip05Name>,
        auth_pubkey: Option<Vec<u8>>
    ) -> Result<Box<dyn AuthzDecision>> {
        self.ready_connection().await;
        let id_blob = hex::decode(&event.id)?;
        let pubkey_blob = hex::decode(&event.pubkey)?;
        let sig_blob = hex::decode(&event.sig)?;
        if let Some(ref mut c) = self.conn {
            let gevent = GrpcEvent {
                id: id_blob,
                pubkey: pubkey_blob,
                sig: sig_blob,
                created_at: event.created_at,
                kind: event.kind,
                content: event.content.clone(),
                tags: tags_to_protobuf(&event.tags),
            };
            let svr_res = c
                .event_admit(EventRequest {
                    event: Some(gevent),
                    ip_addr: Some(ip.to_string()),
                    origin,
                    user_agent,
                    auth_pubkey,
                    nip05: nip05.map(|x| nauthz_grpc::event_request::Nip05Name::from(x)),
                })
                .await?;
            let reply = svr_res.into_inner();
            return Ok(Box::new(reply));
        } else {
            return Err(Error::AuthzError);
        }
    }
}

// Nostr relay server
pub struct NostrRelay {
    bcast: Sender<Event>,
}

#[tonic::async_trait]
impl Relay for NostrRelay {
    async fn broadcast(
        &self,
        request: Request<BroadcastEventRequest>,
    ) -> Result<Response<BroadcastEventResponse>, Status> {
        let req = request.into_inner();
        let grpc_event = req.event.unwrap();
        let content_prefix: String = grpc_event.content.chars().take(40).collect();

        debug!("recvd event for broadcast, kind={:?}, tag_count={}, content_sample={:?}]",
        grpc_event.kind, grpc_event.tags.len(), content_prefix);

        let event = Event {
            id: hex::encode(grpc_event.id),
            pubkey: hex::encode(grpc_event.pubkey),
            delegated_by: None,
            created_at: grpc_event.created_at,
            kind: grpc_event.kind,
            tags: protobuf_to_tags(&grpc_event.tags),
            content: grpc_event.content,
            sig: hex::encode(grpc_event.sig),
            tagidx: None,
        };

        let result = self.bcast.send(event).is_ok();

        Ok(Response::new(BroadcastEventResponse { admitted: result }))
    }
}

pub async fn nostr_grpc_server(
    bcast: Sender<Event>,
    port: u32,
) -> Result<()> {
    let addr = format!("[::1]:{}", port).parse().unwrap();

    // A simple authorization engine that allows kinds 0-3
    let relay = NostrRelay {
        bcast,
    };
    info!("Relay gRPC Server listening on {}", addr);
    // Start serving
    Server::builder()
        .add_service(RelayServer::new(relay))
        .serve(addr)
        .await.ok();
    
    Ok(())
}

fn protobuf_to_tags(tags: &Vec<TagEntry>) -> Vec<Vec<String>> {
    tags.iter()
        .map(|x| x.clone().values.to_vec() )
        .collect()
}
