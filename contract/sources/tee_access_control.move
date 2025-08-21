module seal_integration::seal_manager {
    use sui::object;
    use sui::tx_context;
    use sui::transfer;
    use std::vector;
    use sui::vec_map::{Self, VecMap};

    // Error codes
    const EPolicyNotFound: u64 = 0;       // Policy ID does not match EncryptedFile's policy_id
    const EAccessDenied: u64 = 2;         // Requester not in AccessPolicy rules
    const EBlobIdMismatch: u64 = 3;       // Blob ID in TEEAttestation doesn't match EncryptedFile
    const EEmptyAllowedAddresses: u64 = 4; // Allowed addresses vector is empty
    const EZeroAddressAttestation: u64 = 5; // Attested_by address is 0x0
    const EInvalidId: u64 = 6;            // ID prefix mismatch (added for namespace check)

    // AccessPolicy: Defines who can decrypt the file
    public struct AccessPolicy has key, store {
        id: UID,
        creator: address,
        rules: VecMap<address, bool>, // Maps allowed addresses to true
    }

    // EncryptedFile: Stores metadata about the encrypted file on Walrus
    public struct EncryptedFile has key, store {
        id: UID,
        blob_id: vector<u8>, // Walrus blob ID
        policy_id: ID, // Associated AccessPolicy object ID
        metadata: vector<u8>, // Additional metadata (e.g., file size, type)
    }

    // TEEAttestation: Stores Nautilus TEE attestation data
    public struct TEEAttestation has key, store {
        id: UID,
        enclave_id: vector<u8>, // Optional: empty vector means not provided
        attested_by: address,   // Address of the attester (Nautilus TEE)
        blob_id: vector<u8>,    // Blob ID of the encrypted file
    }

    // Step 1: Create an AccessPolicy to define who can decrypt the file
    public entry fun create_access_policy(
        allowed_addresses: vector<address>,
        ctx: &mut TxContext
    ) {
        assert!(vector::length(&allowed_addresses) > 0, EEmptyAllowedAddresses);

        let mut rules = vec_map::empty<address, bool>();
        let mut i = 0;
        while (i < vector::length(&allowed_addresses)) {
            let addr = *vector::borrow(&allowed_addresses, i);
            vec_map::insert(&mut rules, addr, true);
            i = i + 1;
        };

        let policy = AccessPolicy {
            id: object::new(ctx),
            creator: tx_context::sender(ctx),
            rules,
        };
        transfer::share_object(policy);
    }

    // Step 2: Save metadata of the encrypted file after uploading to Walrus
    public entry fun save_encrypted_file(
        blob_id: vector<u8>,
        policy: &AccessPolicy,
        metadata: vector<u8>,
        ctx: &mut TxContext
    ) {
        let file = EncryptedFile {
            id: object::new(ctx),
            blob_id,
            policy_id: object::uid_to_inner(&policy.id),
            metadata,
        };
        transfer::share_object(file);
    }

    // Step 4: Register Nautilus TEE attestation for the encrypted file
    public entry fun register_tee_attestation(
        enclave_id: vector<u8>, // Can be empty to indicate "not provided"
        blob_id: vector<u8>,
        wallet_address: address,
        ctx: &mut TxContext
    ) {
        let attestation = TEEAttestation {
            id: object::new(ctx),
            enclave_id, // Accept empty vector as "None"
            attested_by: wallet_address,
            blob_id,
        };
        transfer::share_object(attestation);
    }

    // Namespace function to get the AccessPolicy ID as bytes
    public fun namespace(policy: &AccessPolicy): vector<u8> {
        policy.id.to_bytes()
    }

    // Helper function to check if a prefix matches the start of data
    fun is_prefix(prefix: vector<u8>, data: vector<u8>): bool {
        if (vector::length(&prefix) > vector::length(&data)) {
            return false
        };
        let mut i = 0;
        while (i < vector::length(&prefix)) {
            if (*vector::borrow(&prefix, i) != *vector::borrow(&data, i)) {
                return false
            };
            i = i + 1;
        };
        true
    }

    // Step 5: Approve access for the requester to query decryption key shares
    entry fun seal_approve(
        id: vector<u8>, // First parameter as blob_id (identity), per SEAL SDK rule
        file: &EncryptedFile,
        policy: &AccessPolicy,
        attestation: &TEEAttestation,
        wallet_address: address,
    ) {
        // Check if id has the correct prefix (namespace of policy)
        let namespace = namespace(policy);
        assert!(is_prefix(namespace, id), EInvalidId);

        // Verify the blob_id matches the requested identity
        assert!(file.blob_id == id, EBlobIdMismatch);

        // Access control checks
        assert!(file.policy_id == object::uid_to_inner(&policy.id), EPolicyNotFound);
        assert!(vec_map::contains(&policy.rules, &wallet_address), EAccessDenied);
        assert!(attestation.attested_by != @0x0, EZeroAddressAttestation);
        assert!(attestation.blob_id == file.blob_id, EBlobIdMismatch);
        // No return value, aborts on failure as per SEAL SDK rule
    }

    // Utility: Fetch AccessPolicy details (used by SEAL SDK)
    public fun get_access_policy(policy: &AccessPolicy): (address, &VecMap<address, bool>) {
        (policy.creator, &policy.rules)
    }
}