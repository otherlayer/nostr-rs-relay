use std::result;
use std::thread;
use std::io::{stdin, stdout, Read, Write};
use std::sync::atomic::Ordering;
use thiserror::Error;
use tonic::{transport::Server, Request, Response, Status};
use tokio::sync::mpsc;
use tokio::runtime::Builder;

use nauthz_grpc::relay_client::RelayClient;
use nauthz_grpc::authorization_server::{Authorization, AuthorizationServer};
use nauthz_grpc::{Decision, Event as GrpcEvent, EventReply, EventRequest, BroadcastEventRequest, BroadcastEventResponse};

pub type Result<T, E = RelayError> = result::Result<T, E>;

#[derive(Error, Debug)]
pub enum RelayError {
    #[error("Broadcast error")]
    BroadcastError,
    #[error("Tonic GRPC error")]
    TonicError(tonic::Status),
}

impl From<tonic::Status> for RelayError {
    /// Wrap Config error
    fn from(r: tonic::Status) -> Self {
        RelayError::TonicError(r)
    }
}

pub mod nauthz_grpc {
    tonic::include_proto!("nauthz");
}

pub struct EventAuthz {
    allowed_kinds: Vec<u64>,
    external_event_processing: bool,
    admitted_event_tx: mpsc::Sender<GrpcEvent>,
}

#[tonic::async_trait]
impl Authorization for EventAuthz {
    async fn event_admit(
        &self,
        request: Request<EventRequest>,
    ) -> Result<Response<EventReply>, Status> {
        let req = request.into_inner();
        let event = req.event.unwrap();

        if self.external_event_processing {
            self.admitted_event_tx.try_send(event).ok();

            let reply = nauthz_grpc::EventReply {
                decision: Decision::Unspecified as i32,
                message: None,
            };

            return Ok(Response::new(reply))
        }

        let reply;
        let content_prefix: String = event.content.chars().take(40).collect();

        println!("recvd event, [kind={}, origin={:?}, nip05_domain={:?}, tag_count={}, content_sample={:?}]",
                 event.kind, req.origin, req.nip05.map(|x| x.domain), event.tags.len(), content_prefix);
        // Permit any event with a whitelisted kind
        if self.allowed_kinds.contains(&event.kind) {
            println!("This looks fine! (kind={})", event.kind);
            reply = nauthz_grpc::EventReply {
                decision: Decision::Permit as i32,
                message: None,
            };
        } else {
            println!("Blocked! (kind={})", event.kind);
            reply = nauthz_grpc::EventReply {
                decision: Decision::Deny as i32,
                message: Some(format!("kind {} not permitted", event.kind)),
            };
        }
        Ok(Response::new(reply))
    }
}

pub trait BroadcastResponse: Send + Sync {
    fn admitted(&self) -> bool;
}

impl BroadcastResponse for BroadcastEventResponse {
    fn admitted(&self) -> bool {
        self.admitted
    }
}

pub struct NostrRelayService {
    server_addr: String,
    conn: Option<RelayClient<tonic::transport::Channel>>,
}

impl NostrRelayService {
    pub async fn connect(server_addr: &str) -> NostrRelayService {
        let mut eas = NostrRelayService {
            server_addr: server_addr.to_string(),
            conn: None,
        };
        eas.ready_connection().await;
        eas
    }

    pub async fn ready_connection(self: &mut Self) {
        if self.conn.is_none() {
            let client = RelayClient::connect(self.server_addr.to_string()).await;
            if let Err(ref msg) = client {
                println!("could not connect to nostr relay GRPC server: {:?}", msg);
            } else {
                println!("connected to nostr relay GRPC server");
            }
            self.conn = client.ok();
        }
    }

    pub async fn broadcast(
        self: &mut Self,
        event: GrpcEvent,
    ) -> Result<Box<dyn BroadcastResponse>> {
        self.ready_connection().await;

        if let Some(ref mut c) = self.conn {
            let svr_res = c.broadcast( BroadcastEventRequest {
                event: Some(event),
            }).await?;

            let response = svr_res.into_inner();

            return Ok(Box::new(response));
        } else {
            return Err(RelayError::BroadcastError);
        }
    }
}

pub fn wait_for_server() {
    let mut stdout = stdout();
    stdout.write(b"Start Nostr server and press any key...").unwrap();
    stdout.flush().unwrap();
    stdin().read(&mut [0]).unwrap();
}

pub async fn relay_grpc_client(
    mut submitted_event_rx: mpsc::Receiver<GrpcEvent>,
) -> Result<()> {
    wait_for_server();

    let mut relay_grpc_client = NostrRelayService::connect("http://[::1]:50050").await;

    println!("Relay GPRC client started");

    loop {
        // call blocking read on channel
        let next_event = submitted_event_rx.recv().await;
        // if the channel has closed, we will never get work
        if next_event.is_none() {
            break;
        }

        let event = next_event.unwrap();

        let response = relay_grpc_client.broadcast(event).await;

        match response {
            Ok(_) => {
                continue
            },
            Err(e) => {
                println!("GRPC server error: {:?}", e);
            },
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse().unwrap();
    let external_event_processing = true;

    let (
        admitted_event_tx, 
        admitted_event_rx
    ) = mpsc::channel::<GrpcEvent>(100);

    let handle = thread::spawn(move || {
        let rt = Builder::new_multi_thread()
        .enable_all()
        .thread_name_fn(|| {
            // give each thread a unique numeric name
            static ATOMIC_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let id = ATOMIC_ID.fetch_add(1,Ordering::SeqCst);
            format!("tokio-ws-{id}")
        })
        .max_blocking_threads(4)
        .build()
        .unwrap();

        rt.block_on( async {
            if external_event_processing == true {
                tokio::task::spawn(relay_grpc_client(admitted_event_rx));
            }

            // A simple authorization engine that allows kinds 0-3
            let checker = EventAuthz {
                allowed_kinds: vec![0, 1, 2, 3],
                external_event_processing,
                admitted_event_tx,
            };
    
            println!("EventAuthz Server listening on {}", addr);
            // Start serving
            let server = Server::builder()
                .add_service(AuthorizationServer::new(checker))
                .serve(addr);

            if let Err(e) = server.await {
                eprintln!("server error: {e}");
            }
        });
    });

    handle.join().unwrap();

    Ok(())
}
