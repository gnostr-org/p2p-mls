use colored::Colorize;
use docopt::Docopt;
use openmls::prelude::TlsSerializeTrait;

use crate::{error::NodeError, node::Node};

// Write the Docopt usage string.
const USAGE: &str = "
Usage: node create
       node join
       node send <message>
";

type Message = Vec<u8>;

// Command line helper for Node actions
pub fn parse_stdin(node: &mut Node, line: String) -> Result<Message, NodeError> {
    let args_res = Docopt::new(USAGE).and_then(|d| d.argv(line.split(' ')).parse());
    let mut msg = Vec::new();
    match args_res {
        Ok(args) => {
            let user_message = args.get_str("<message>");
            if args.get_bool("create") {
                println!("Creating new group.");
                node.join_new_group();
            } else if args.get_bool("join") {
                println!("Joining group.");
                msg = node
                    .get_key_package()
                    .tls_serialize_detached()
                    .expect("key should serialize");
            } else if !user_message.is_empty() {
                msg = node
                    .create_message(user_message)?
                    .tls_serialize_detached()
                    .expect("message should serialize");
                println!("{}: {}", "me".to_string().red(), user_message);
            }
        }
        Err(e) => {
            println!("{}", e);
        }
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_command_makes_node_group_leader() {
        let mut node = Node::default();
        assert!(!node.is_group_leader());
        let msg = parse_stdin(&mut node, "node create".to_string()).unwrap();
        assert!(node.is_group_leader());
        // create does not produce a wire message
        assert!(msg.is_empty());
    }

    #[test]
    fn join_command_returns_serialized_key_package() {
        let mut node = Node::default();
        let msg = parse_stdin(&mut node, "node join".to_string()).unwrap();
        // A key package serializes to a non-empty byte vector
        assert!(!msg.is_empty());
    }

    #[test]
    fn send_command_produces_message_when_in_group() {
        let mut alice = Node::default();
        alice.join_new_group();
        let msg = parse_stdin(&mut alice, "node send hello".to_string()).unwrap();
        assert!(!msg.is_empty());
    }

    #[test]
    fn send_command_fails_when_not_in_group() {
        let mut node = Node::default();
        let result = parse_stdin(&mut node, "node send hello".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn invalid_command_returns_empty_message() {
        let mut node = Node::default();
        // docopt prints the usage and returns no message for unrecognised input
        let msg = parse_stdin(&mut node, "node unknown".to_string()).unwrap();
        assert!(msg.is_empty());
    }
}
