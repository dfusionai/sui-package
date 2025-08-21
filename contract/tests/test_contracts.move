#[test_only]
module seal_integration::test_seal_manager {
    use seal_integration::seal_manager::{Self, AccessPolicy, EncryptedFile, TEEAttestation};
    use sui::test_scenario::{Self as ts, Scenario};
    use sui::test_utils::assert_eq;
    use sui::vec_map::{Self, VecMap};
    use sui::vector;

    // Test addresses
    const ADMIN: address = @0xAD;
    const USER1: address = @0xB0B;
    const USER2: address = @0xC0C;
    const TEE: address = @0xTEE;

    // Test data
    const BLOB_ID: vector<u8> = b"test-blob-id";
    const METADATA: vector<u8> = b"{\"type\":\"test\",\"size\":100}";
    const ENCLAVE_ID: vector<u8> = b"test-enclave";

    fun setup_test(): Scenario {
        let scenario = ts::begin(ADMIN);
        scenario
    }

    #[test]
    fun test_create_access_policy() {
        let scenario = setup_test();
        let admin = ts::next_tx(&mut scenario, ADMIN);
        
        // Create policy with two users
        let allowed_addresses = vector[USER1, USER2];
        seal_manager::create_access_policy(allowed_addresses, &mut admin);
        
        // Verify policy was created
        let policy = ts::take_shared<AccessPolicy>(&scenario);
        let (creator, rules) = seal_manager::get_access_policy(&policy);
        
        assert_eq(creator, ADMIN);
        assert_eq(vec_map::length(&rules), 2);
        assert!(vec_map::contains(&rules, &USER1));
        assert!(vec_map::contains(&rules, &USER2));
        
        ts::return_shared(policy);
        ts::end(scenario);
    }

    #[test]
    fun test_save_encrypted_file() {
        let scenario = setup_test();
        let admin = ts::next_tx(&mut scenario, ADMIN);
        
        // Create policy first
        let allowed_addresses = vector[USER1];
        seal_manager::create_access_policy(allowed_addresses, &mut admin);
        let policy = ts::take_shared<AccessPolicy>(&scenario);
        
        // Save encrypted file
        seal_manager::save_encrypted_file(BLOB_ID, &policy, METADATA, &mut admin);
        
        // Verify file was created
        let file = ts::take_shared<EncryptedFile>(&scenario);
        assert_eq(file.blob_id, BLOB_ID);
        assert_eq(file.metadata, METADATA);
        
        ts::return_shared(file);
        ts::return_shared(policy);
        ts::end(scenario);
    }

    #[test]
    fun test_register_tee_attestation() {
        let scenario = setup_test();
        let tee = ts::next_tx(&mut scenario, TEE);
        
        // Register attestation
        seal_manager::register_tee_attestation(ENCLAVE_ID, BLOB_ID, &mut tee);
        
        // Verify attestation was created
        let attestation = ts::take_shared<TEEAttestation>(&scenario);
        assert_eq(attestation.enclave_id, ENCLAVE_ID);
        assert_eq(attestation.blob_id, BLOB_ID);
        assert_eq(attestation.attested_by, TEE);
        
        ts::return_shared(attestation);
        ts::end(scenario);
    }

    #[test]
    fun test_seal_approve_success() {
        let scenario = setup_test();
        
        // Setup: Create policy, file, and attestation
        let admin = ts::next_tx(&mut scenario, ADMIN);
        let allowed_addresses = vector[USER1];
        seal_manager::create_access_policy(allowed_addresses, &mut admin);
        let policy = ts::take_shared<AccessPolicy>(&scenario);
        
        seal_manager::save_encrypted_file(BLOB_ID, &policy, METADATA, &mut admin);
        let file = ts::take_shared<EncryptedFile>(&scenario);
        
        let tee = ts::next_tx(&mut scenario, TEE);
        seal_manager::register_tee_attestation(ENCLAVE_ID, BLOB_ID, &mut tee);
        let attestation = ts::take_shared<TEEAttestation>(&scenario);
        
        // Test: User1 tries to approve access
        let user1 = ts::next_tx(&mut scenario, USER1);
        seal_manager::seal_approve(BLOB_ID, &file, &policy, &attestation, &mut user1);
        
        ts::return_shared(attestation);
        ts::return_shared(file);
        ts::return_shared(policy);
        ts::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = seal_manager::EAccessDenied)]
    fun test_seal_approve_access_denied() {
        let scenario = setup_test();
        
        // Setup: Create policy with only USER1
        let admin = ts::next_tx(&mut scenario, ADMIN);
        let allowed_addresses = vector[USER1];
        seal_manager::create_access_policy(allowed_addresses, &mut admin);
        let policy = ts::take_shared<AccessPolicy>(&scenario);
        
        seal_manager::save_encrypted_file(BLOB_ID, &policy, METADATA, &mut admin);
        let file = ts::take_shared<EncryptedFile>(&scenario);
        
        let tee = ts::next_tx(&mut scenario, TEE);
        seal_manager::register_tee_attestation(ENCLAVE_ID, BLOB_ID, &mut tee);
        let attestation = ts::take_shared<TEEAttestation>(&scenario);
        
        // Test: USER2 (not in policy) tries to approve access
        let user2 = ts::next_tx(&mut scenario, USER2);
        seal_manager::seal_approve(BLOB_ID, &file, &policy, &attestation, &mut user2);
        
        ts::return_shared(attestation);
        ts::return_shared(file);
        ts::return_shared(policy);
        ts::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = seal_manager::EBlobIdMismatch)]
    fun test_seal_approve_blob_id_mismatch() {
        let scenario = setup_test();
        
        // Setup: Create policy and file
        let admin = ts::next_tx(&mut scenario, ADMIN);
        let allowed_addresses = vector[USER1];
        seal_manager::create_access_policy(allowed_addresses, &mut admin);
        let policy = ts::take_shared<AccessPolicy>(&scenario);
        
        seal_manager::save_encrypted_file(BLOB_ID, &policy, METADATA, &mut admin);
        let file = ts::take_shared<EncryptedFile>(&scenario);
        
        // Create attestation with different blob ID
        let tee = ts::next_tx(&mut scenario, TEE);
        seal_manager::register_tee_attestation(ENCLAVE_ID, b"different-blob", &mut tee);
        let attestation = ts::take_shared<TEEAttestation>(&scenario);
        
        // Test: Try to approve with mismatched blob ID
        let user1 = ts::next_tx(&mut scenario, USER1);
        seal_manager::seal_approve(BLOB_ID, &file, &policy, &attestation, &mut user1);
        
        ts::return_shared(attestation);
        ts::return_shared(file);
        ts::return_shared(policy);
        ts::end(scenario);
    }
}
