use lazy_static;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{signatures::Signer, OpenMlsProvider};

lazy_static! {
    static ref MLS_GROUP_CREATE_CONFIG: MlsGroupCreateConfig = MlsGroupCreateConfig::builder()
        .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519)
        .padding_size(100)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            10,   // out_of_order_tolerance
            2000, // maximum_forward_distance
        ))
        .use_ratchet_tree_extension(true)
        .build();
}

/// Create a credential bundle from an identity and store the signing key in the provider.
///
/// Returns the [`CredentialWithKey`] and the [`SignatureKeyPair`] needed for signing.
pub fn generate_credential_bundle_from_identity(
    identity: Vec<u8>,
    backend: &impl OpenMlsProvider,
) -> Result<(CredentialWithKey, SignatureKeyPair), ()> {
    let credential = BasicCredential::new(identity);
    let signature_keys = SignatureKeyPair::new(SignatureScheme::ED25519).map_err(|_| ())?;
    signature_keys
        .store(backend.storage())
        .map_err(|_| ())?;
    Ok((
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.public().into(),
        },
        signature_keys,
    ))
}

/// Build a [`KeyPackage`] for the given credential and signer and store the bundle in the
/// provider's key store.
pub fn generate_key_package_bundle(
    ciphersuite: Ciphersuite,
    credential_with_key: CredentialWithKey,
    signer: &SignatureKeyPair,
    backend: &impl OpenMlsProvider,
) -> Result<KeyPackage, KeyPackageNewError> {
    KeyPackage::builder()
        .build(ciphersuite, backend, signer, credential_with_key)
        .map(|bundle| bundle.key_package().clone())
}

/// Create a fresh MLS group owned by `credential_with_key` / `signer`.
pub fn generate_mls_group(
    backend: &impl OpenMlsProvider,
    signer: &impl Signer,
    credential_with_key: CredentialWithKey,
) -> MlsGroup {
    let group_id = GroupId::from_slice(b"Test Group");
    MlsGroup::new_with_group_id(
        backend,
        signer,
        &MLS_GROUP_CREATE_CONFIG,
        group_id,
        credential_with_key,
    )
    .expect("An unexpected error occurred.")
}

/// Join an existing group from a [`Welcome`] message.
pub fn generate_mls_group_from_welcome(
    backend: &OpenMlsRustCrypto,
    welcome: Welcome,
) -> Result<MlsGroup, WelcomeError<openmls_rust_crypto::MemoryStorageError>> {
    StagedWelcome::new_from_welcome(backend, MLS_GROUP_CREATE_CONFIG.join_config(), welcome, None)
        .and_then(|staged| staged.into_group(backend))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use tls_codec::Serialize as TlsSerialize;

    const CIPHERSUITE: Ciphersuite =
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

    #[test]
    fn smoke_test() -> Result<(), ()> {
        let alice_backend = &OpenMlsRustCrypto::default();
        let bob_backend = &OpenMlsRustCrypto::default();

        let (bob_credential, bob_signer) =
            generate_credential_bundle_from_identity("Bob1".into(), bob_backend).unwrap();
        let (alice_credential, alice_signer) =
            generate_credential_bundle_from_identity("Alice1".into(), alice_backend).unwrap();

        let bob_key_package =
            generate_key_package_bundle(CIPHERSUITE, bob_credential, &bob_signer, bob_backend)
                .unwrap();

        let group_id = GroupId::from_slice(b"Test Group");

        let mut alice_group = MlsGroup::new_with_group_id(
            alice_backend,
            &alice_signer,
            &MLS_GROUP_CREATE_CONFIG,
            group_id,
            alice_credential,
        )
        .expect("An unexpected error occurred.");

        let (_, welcome, _) = alice_group
            .add_members(alice_backend, &alice_signer, &[bob_key_package])
            .expect("Could not add members.");

        alice_group
            .merge_pending_commit(alice_backend)
            .expect("error merging pending commit");

        // Serialize + deserialize to extract the Welcome (production-safe path).
        let welcome_bytes = welcome.tls_serialize_detached().unwrap();
        let welcome_msg_in = MlsMessageIn::tls_deserialize_exact_bytes(&welcome_bytes).unwrap();
        let welcome_inner = match welcome_msg_in.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => panic!("expected a Welcome"),
        };
        let mut bob_group = StagedWelcome::new_from_welcome(
            bob_backend,
            MLS_GROUP_CREATE_CONFIG.join_config(),
            welcome_inner,
            None,
        )
        .expect("Error creating staged welcome")
        .into_group(bob_backend)
        .expect("Error joining group from Welcome");

        let message_alice = b"Hi, I'm Alice!";
        let mls_message_out = alice_group
            .create_message(alice_backend, &alice_signer, message_alice)
            .expect("Error creating application message.");

        // Serialize + deserialize to convert MlsMessageOut → MlsMessageIn.
        let msg_bytes = mls_message_out.tls_serialize_detached().unwrap();
        let msg_in = MlsMessageIn::tls_deserialize_exact_bytes(&msg_bytes).unwrap();
        let processed_message = bob_group
            .process_message(
                bob_backend,
                msg_in
                    .try_into_protocol_message()
                    .expect("should be a protocol message"),
            )
            .expect("Could not process message.");

        if let ProcessedMessageContent::ApplicationMessage(application_message) =
            processed_message.into_content()
        {
            assert_eq!(application_message.into_bytes(), b"Hi, I'm Alice!");
        }
        Ok(())
    }

    #[test]
    fn different_identities_produce_distinct_credentials() {
        let backend = &OpenMlsRustCrypto::default();
        let (cred_a, _) =
            generate_credential_bundle_from_identity("Alice".into(), backend).unwrap();
        let (cred_b, _) =
            generate_credential_bundle_from_identity("Bob".into(), backend).unwrap();
        assert_ne!(
            cred_a.credential.serialized_content(),
            cred_b.credential.serialized_content()
        );
    }

    #[test]
    fn key_package_can_be_hashed() {
        let backend = &OpenMlsRustCrypto::default();
        let (credential, signer) =
            generate_credential_bundle_from_identity("Charlie".into(), backend).unwrap();
        let kp = generate_key_package_bundle(CIPHERSUITE, credential, &signer, backend).unwrap();
        kp.hash_ref(backend.crypto())
            .expect("key package should be hashable");
    }

    #[test]
    fn generate_mls_group_creates_empty_group() {
        let backend = &OpenMlsRustCrypto::default();
        let (credential, signer) =
            generate_credential_bundle_from_identity("Dave".into(), backend).unwrap();
        let group = generate_mls_group(backend, &signer, credential);
        assert_eq!(group.members().count(), 1);
    }

    #[test]
    fn generate_mls_group_from_welcome_round_trips() {
        let creator_backend = &OpenMlsRustCrypto::default();
        let joiner_backend = &OpenMlsRustCrypto::default();

        let (creator_cred, creator_signer) =
            generate_credential_bundle_from_identity("Creator".into(), creator_backend).unwrap();
        let (joiner_cred, joiner_signer) =
            generate_credential_bundle_from_identity("Joiner".into(), joiner_backend).unwrap();

        let joiner_kp =
            generate_key_package_bundle(CIPHERSUITE, joiner_cred, &joiner_signer, joiner_backend)
                .unwrap();

        let mut creator_group =
            generate_mls_group(creator_backend, &creator_signer, creator_cred);
        let (_, welcome, _) = creator_group
            .add_members(creator_backend, &creator_signer, &[joiner_kp])
            .expect("Could not add member");
        creator_group
            .merge_pending_commit(creator_backend)
            .expect("merge failed");

        let welcome_bytes = welcome.tls_serialize_detached().unwrap();
        let welcome_msg_in = MlsMessageIn::tls_deserialize_exact_bytes(&welcome_bytes).unwrap();
        let welcome_inner = match welcome_msg_in.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => panic!("expected a Welcome"),
        };
        let joiner_group = generate_mls_group_from_welcome(joiner_backend, welcome_inner)
            .expect("joiner should be able to join from welcome");
        assert_eq!(joiner_group.members().count(), 2);
    }
}
