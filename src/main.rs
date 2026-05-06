//! Much of the boilerplate copied from
//! https://github.com/libp2p/rust-libp2p/blob/master/examples/chat.rs

use colored::Colorize;
use futures::lock::Mutex;
use futures::StreamExt;
use libp2p::{
    floodsub::{self, Behaviour as Floodsub, Event as FloodsubEvent},
    mdns, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, PeerId, Swarm,
};
use mls::cli::parse_stdin;
use mls::node::Node;
use openmls::prelude::{
    KeyPackage, MlsMessageOut, TlsDeserializeTrait, TlsSerializeTrait, Welcome,
};
use std::error::Error;
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let node = Node::default();
    let id_keys = node.get_network_keypair();

    // Create a Swarm to manage peers and events.
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(id_keys)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let local_peer_id = PeerId::from(key.public());
            Ok(MyBehaviour {
                floodsub: Floodsub::new(local_peer_id),
                mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?,
            })
        })?
        .build();

    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let (out_msg_sender, out_msg_receiver) = mpsc::unbounded_channel::<Vec<u8>>();
    let (in_msg_sender, mut in_msg_receiver) = mpsc::unbounded_channel::<(PeerId, Vec<u8>)>();

    let cloned_out = out_msg_sender.clone();

    // Spawn away the event loop that will keep the swarm going.
    tokio::spawn(network_event_loop(swarm, out_msg_receiver, in_msg_sender));

    // For demonstration purposes, we create a dedicated task that handles incoming messages.
    let arc_node = Arc::new(Mutex::new(node));
    let cloned_arc_node = Arc::clone(&arc_node);
    tokio::spawn(async move {
        loop {
            let Some((peer, message)) = in_msg_receiver.recv().await else {
                break;
            };
            let inner_node = &mut *cloned_arc_node.lock().await;
            let bytes_array: &[u8] = &message;

            if let Ok(key_package) = KeyPackage::try_from(bytes_array) {
                if inner_node.is_group_leader() {
                    let (msg_out, welcome) = inner_node.add_member_to_group(key_package);
                    let welcome_serialized = welcome.tls_serialize_detached().unwrap();
                    let msg_out_serialized = msg_out.tls_serialize_detached().unwrap();
                    cloned_out.send(welcome_serialized).unwrap();
                    cloned_out.send(msg_out_serialized).unwrap();
                    println!(
                        "Received key package from {:?}, added to group and sent back welcome message and join message for existing members",
                        peer
                    );
                }
            } else if let Ok(msg_out) = MlsMessageOut::try_from_bytes(bytes_array) {
                match inner_node.parse_message(msg_out) {
                    Ok(msg) => {
                        if let Some(str_msg) = msg {
                            println!("{}:{}", peer.to_string().red(), str_msg.blue());
                        }
                    }
                    Err(_) => {
                        println!("Could not parse message");
                    }
                }
            } else if let Ok(welcome) = Welcome::tls_deserialize(&mut &*bytes_array) {
                if let Ok(()) = inner_node.join_existing_group(welcome) {
                    println!("Received welcome message from from {:?}", peer);
                } else {
                    println!("Could not join group");
                }
            } else {
                println!("Received: '{:?}' from {:?}", message, peer);
            }
        }
    });

    let stdin = BufReader::new(io::stdin());
    let mut lines = stdin.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let inner_node = &mut *arc_node.lock().await;
        match parse_stdin(inner_node, line) {
            Ok(msg) => {
                out_msg_sender.send(msg).unwrap();
            }
            Err(e) => {
                println!("{}", e);
            }
        }
    }

    Ok(())
}

/// Defines the event-loop of our application's network layer.
///
/// The event-loop handles some network events itself like mDNS and interacts with the rest
/// of the application via channels.
/// Conceptually, this is an actor-ish design.
async fn network_event_loop(
    mut swarm: Swarm<MyBehaviour>,
    mut receiver: mpsc::UnboundedReceiver<Vec<u8>>,
    sender: mpsc::UnboundedSender<(PeerId, Vec<u8>)>,
) {
    // Create a Floodsub topic
    let chat = floodsub::Topic::new("chat");

    swarm.behaviour_mut().floodsub.subscribe(chat.clone());

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("Listening on {}", address);
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        println!("Connected to {} on {}", peer_id, endpoint.get_remote_address());
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        println!("Disconnected from {}", peer_id);
                    }
                    SwarmEvent::Behaviour(MyOutEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer, _) in list {
                            swarm.behaviour_mut().floodsub.add_node_to_partial_view(peer);
                        }
                    }
                    SwarmEvent::Behaviour(MyOutEvent::Mdns(mdns::Event::Expired(list))) => {
                        for (peer, _) in list {
                            if !swarm.behaviour().mdns.discovered_nodes().any(|p| p == &peer) {
                                swarm.behaviour_mut().floodsub.remove_node_from_partial_view(&peer);
                            }
                        }
                    }
                    SwarmEvent::Behaviour(MyOutEvent::Floodsub(FloodsubEvent::Message(message)))
                        if message.topics.contains(&chat) =>
                    {
                        sender.send((message.source, message.data.to_vec())).unwrap();
                    }
                    _ => {} // ignore all other events
                }
            },
            Some(message) = receiver.recv() => {
                swarm.behaviour_mut().floodsub.publish(chat.clone(), message);
            }
        }
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "MyOutEvent")]
struct MyBehaviour {
    floodsub: Floodsub,
    mdns: mdns::tokio::Behaviour,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum MyOutEvent {
    Floodsub(FloodsubEvent),
    Mdns(mdns::Event),
}

impl From<FloodsubEvent> for MyOutEvent {
    fn from(event: FloodsubEvent) -> MyOutEvent {
        MyOutEvent::Floodsub(event)
    }
}

impl From<mdns::Event> for MyOutEvent {
    fn from(event: mdns::Event) -> MyOutEvent {
        MyOutEvent::Mdns(event)
    }
}
