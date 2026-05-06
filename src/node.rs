use libp2p::{identity::Keypair, PeerId};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::{
    crypto::{
        generate_credential_bundle_from_identity, generate_key_package_bundle, generate_mls_group,
        generate_mls_group_from_welcome,
    },
    error::NodeError,
};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

struct Identity {
    network_key: Keypair,
    credential_with_key: CredentialWithKey,
    signer: SignatureKeyPair,
    key_package: KeyPackage,
}

pub struct Node {
    backend: OpenMlsRustCrypto,
    mls_group: Option<MlsGroup>,
    identity: Identity,
    is_group_leader: bool,
}

impl Default for Node {
    fn default() -> Node {
        let backend = OpenMlsRustCrypto::default();
        let network_key = Keypair::generate_ed25519();
        let peer_id = PeerId::from(network_key.public());
        let (credential_with_key, signer) =
            generate_credential_bundle_from_identity(peer_id.to_bytes().to_vec(), &backend)
                .expect("error creating credential");
        let key_package =
            generate_key_package_bundle(CIPHERSUITE, credential_with_key.clone(), &signer, &backend)
                .expect("should have no problem with key package");

        Node {
            backend,
            mls_group: None,
            is_group_leader: false,
            identity: Identity {
                network_key,
                credential_with_key,
                signer,
                key_package,
            },
        }
    }
}

impl Node {
    pub fn join_new_group(&mut self) {
        self.mls_group = Some(generate_mls_group(
            &self.backend,
            &self.identity.signer,
            self.identity.credential_with_key.clone(),
        ));
        self.is_group_leader = true;
    }

    pub fn is_group_leader(&self) -> bool {
        self.is_group_leader
    }

    /// Add a member to the group.
    ///
    /// Returns the commit message (for existing members) and the welcome message (for the new
    /// member).
    pub fn add_member_to_group(
        &mut self,
        key_package: KeyPackage,
    ) -> (MlsMessageOut, MlsMessageOut) {
        let group = self.mls_group.as_mut().expect("group expected");
        let (commit, welcome, _) = group
            .add_members(&self.backend, &self.identity.signer, &[key_package])
            .expect("Could not add members.");
        group
            .merge_pending_commit(&self.backend)
            .expect("error merging pending commit");
        (commit, welcome)
    }

    pub fn join_existing_group(&mut self, welcome: Welcome) -> Result<(), NodeError> {
        self.mls_group = Some(generate_mls_group_from_welcome(&self.backend, welcome)?);
        self.is_group_leader = false;
        Ok(())
    }

    pub fn create_message(&mut self, msg: &str) -> Result<MlsMessageOut, NodeError> {
        Ok(self
            .mls_group
            .as_mut()
            .ok_or_else(|| NodeError("Group required to create message".to_string()))?
            .create_message(&self.backend, &self.identity.signer, msg.as_bytes())
            .expect("Error creating application message."))
    }

    pub fn get_key_package(&self) -> KeyPackage {
        self.identity.key_package.clone()
    }

    /// Validate an incoming [`KeyPackageIn`] and convert it to a verified [`KeyPackage`].
    pub fn validate_key_package_in(
        &self,
        kp_in: KeyPackageIn,
    ) -> Result<KeyPackage, KeyPackageVerifyError> {
        kp_in.validate(self.backend.crypto(), ProtocolVersion::default())
    }

    pub fn get_network_keypair(&self) -> Keypair {
        self.identity.network_key.clone()
    }

    /// Parse an incoming MLS message.
    ///
    /// Returns `Ok(Some(text))` for application messages, `Ok(None)` for commits / when not yet
    /// in a group.
    pub fn parse_message(&mut self, msg: MlsMessageIn) -> Result<Option<String>, NodeError> {
        if self.mls_group.is_none() {
            return Ok(None);
        }
        let protocol_msg = msg
            .try_into_protocol_message()
            .map_err(|e| NodeError(e.to_string()))?;

        let processed = self
            .mls_group
            .as_mut()
            .expect("group")
            .process_message(&self.backend, protocol_msg)?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => Ok(Some(
                String::from_utf8(app_msg.into_bytes())
                    .map_err(|e| NodeError(e.to_string()))?,
            )),
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.mls_group
                    .as_mut()
                    .expect("group")
                    .merge_staged_commit(&self.backend, *staged_commit)
                    .map_err(|e| NodeError(e.to_string()))?;
                Ok(None)
            }
            _ => Ok(None),
        }
    }
}

/// Serialize an [`MlsMessageOut`] to bytes, then deserialize as [`MlsMessageIn`].
/// This simulates the on-wire round-trip and is used in tests.
#[cfg(test)]
fn msg_out_to_in(msg: MlsMessageOut) -> MlsMessageIn {
    use tls_codec::Serialize as _;
    let bytes = msg.tls_serialize_detached().expect("serialization failed");
    MlsMessageIn::tls_deserialize_exact_bytes(&bytes).expect("deserialization failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_codec::Serialize as _;

    #[test]
    fn default_node_is_not_group_leader() {
        let node = Node::default();
        assert!(!node.is_group_leader());
    }

    #[test]
    fn join_new_group_makes_node_leader() {
        let mut node = Node::default();
        node.join_new_group();
        assert!(node.is_group_leader());
    }

    #[test]
    fn create_message_without_group_returns_error() {
        let mut node = Node::default();
        let result = node.create_message("hello");
        assert!(result.is_err());
    }

    #[test]
    fn parse_message_without_group_returns_none() {
        let mut alice = Node::default();
        alice.join_new_group();
        let msg_out = alice.create_message("ping").unwrap();
        let mut observer = Node::default();
        // parse_message returns Ok(None) when there is no group
        let result = observer.parse_message(msg_out_to_in(msg_out)).unwrap();
        assert!(result.is_none());
    }

    fn add_bob_to_alice_group(alice: &mut Node, bob: &mut Node) -> Welcome {
        let bob_kp = bob.get_key_package();
        let (_, welcome_msg) = alice.add_member_to_group(bob_kp);
        // Serialize and re-deserialize to extract the Welcome (production-safe path).
        let bytes = welcome_msg.tls_serialize_detached().unwrap();
        let msg_in = MlsMessageIn::tls_deserialize_exact_bytes(&bytes).unwrap();
        match msg_in.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => panic!("expected a Welcome message"),
        }
    }

    #[test]
    fn smoke_test() {
        let mut alice = Node::default();
        alice.join_new_group();
        let mut bob = Node::default();
        let welcome = add_bob_to_alice_group(&mut alice, &mut bob);
        bob.join_existing_group(welcome).expect("");
        let msg_out = alice.create_message("hi bob").unwrap();
        let msg = bob
            .parse_message(msg_out_to_in(msg_out))
            .expect("message parsed")
            .unwrap();
        assert_eq!(msg, "hi bob");
    }

    #[test]
    fn bidirectional_messaging() {
        let mut alice = Node::default();
        alice.join_new_group();
        let mut bob = Node::default();
        let welcome = add_bob_to_alice_group(&mut alice, &mut bob);
        bob.join_existing_group(welcome).unwrap();

        // Alice → Bob
        let msg = alice.create_message("hello bob").unwrap();
        let received = bob.parse_message(msg_out_to_in(msg)).unwrap().unwrap();
        assert_eq!(received, "hello bob");

        // Bob → Alice
        let reply = bob.create_message("hello alice").unwrap();
        let received = alice.parse_message(msg_out_to_in(reply)).unwrap().unwrap();
        assert_eq!(received, "hello alice");
    }

    #[test]
    fn get_key_package_returns_cloneable_value() {
        let node = Node::default();
        let kp1 = node.get_key_package();
        let kp2 = node.get_key_package();
        let s1 = kp1.tls_serialize_detached().unwrap();
        let s2 = kp2.tls_serialize_detached().unwrap();
        assert_eq!(s1, s2);
    }
}
