#[test_only]
module seal_integration::test_seal_manager {
    use seal_integration::seal_manager::{Self, AccessPolicy, EncryptedFile, TEEAttestation};
    use sui::test_scenario::{Self as ts, Scenario};
    use sui::test_utils::assert_eq;
    use sui::vec_map;

    // Test addresses
    const ADMIN: address = @0xAD;
    const USER1: address = @0xB0B;
    const USER2: address = @0xC0C;
    const TEE: address = @0x123;
    const ZERO_ADDRESS: address = @0x0;

    // Test data - Using namespace as the blob_id to satisfy both checks
    const METADATA: vector<u8> = b"{\"type\":\"test\",\"size\":100}";
    const ENCLAVE_ID: vector<u8> = b"test-enclave";

    fun setup_test(): Scenario {
        let scenario = ts::begin(ADMIN);
        scenario
    }

    #[test]
    fun test_create_access_policy() {
        let mut scenario = setup_test();
        
        // Create policy with two users
        ts::next_tx(&mut scenario, ADMIN);
        {
            let allowed_addresses = vector[USER1, USER2];
            seal_manager::create_access_policy(allowed_addresses, ts::ctx(&mut scenario));
        };
        
        // Verify policy was created
        ts::next_tx(&mut scenario, ADMIN);
        {
            let policy = ts::take_shared<AccessPolicy>(&scenario);
            let (creator, rules) = seal_manager::get_access_policy(&policy);
            
            assert_eq(creator, ADMIN);
            assert_eq(vec_map::size(rules), 2);
            let user1 = USER1;
            let user2 = USER2;
            assert!(vec_map::contains(rules, &user1));
            assert!(vec_map::contains(rules, &user2));
            
            ts::return_shared(policy);
        };
        ts::end(scenario);
    }

    #[test]
    fun test_save_encrypted_file() {
        let mut scenario = setup_test();
        
        // Create policy first
        ts::next_tx(&mut scenario, ADMIN);
        {
            let allowed_addresses = vector[USER1];
            seal_manager::create_access_policy(allowed_addresses, ts::ctx(&mut scenario));
        };
        
        // Save encrypted file using namespace as blob_id
        ts::next_tx(&mut scenario, ADMIN);
        {
            let policy = ts::take_shared<AccessPolicy>(&scenario);
            let namespace = seal_manager::namespace(&policy);
            seal_manager::save_encrypted_file(namespace, &policy, METADATA, ts::ctx(&mut scenario));
            ts::return_shared(policy);
        };
        
        // Verify file was created
        ts::next_tx(&mut scenario, ADMIN);
        {
            let file = ts::take_shared<EncryptedFile>(&scenario);
            ts::return_shared(file);
        };
        ts::end(scenario);
    }

    #[test]
    fun test_register_tee_attestation() {
        let mut scenario = setup_test();
        
        // Create policy first to get namespace
        ts::next_tx(&mut scenario, ADMIN);
        {
            let allowed_addresses = vector[USER1];
            seal_manager::create_access_policy(allowed_addresses, ts::ctx(&mut scenario));
        };
        
        // Register attestation using namespace as blob_id
        ts::next_tx(&mut scenario, TEE);
        {
            let policy = ts::take_shared<AccessPolicy>(&scenario);
            let namespace = seal_manager::namespace(&policy);
            seal_manager::register_tee_attestation(ENCLAVE_ID, namespace, TEE, ts::ctx(&mut scenario));
            ts::return_shared(policy);
        };
        
        // Verify attestation was created
        ts::next_tx(&mut scenario, TEE);
        {
            let attestation = ts::take_shared<TEEAttestation>(&scenario);
            ts::return_shared(attestation);
        };
        ts::end(scenario);
    }

    #[test]
    fun test_seal_approve_success() {
        let mut scenario = setup_test();
        
        // Setup: Create policy
        ts::next_tx(&mut scenario, ADMIN);
        {
            let allowed_addresses = vector[USER1];
            seal_manager::create_access_policy(allowed_addresses, ts::ctx(&mut scenario));
        };
        
        // Save encrypted file using namespace as blob_id
        ts::next_tx(&mut scenario, ADMIN);
        {
            let policy = ts::take_shared<AccessPolicy>(&scenario);
            let namespace = seal_manager::namespace(&policy);
            seal_manager::save_encrypted_file(namespace, &policy, METADATA, ts::ctx(&mut scenario));
            ts::return_shared(policy);
        };
        
        // Register TEE attestation using same namespace
        ts::next_tx(&mut scenario, TEE);
        {
            let policy = ts::take_shared<AccessPolicy>(&scenario);
            let namespace = seal_manager::namespace(&policy);
            seal_manager::register_tee_attestation(ENCLAVE_ID, namespace, TEE, ts::ctx(&mut scenario));
            ts::return_shared(policy);
        };
        
        // Test: User1 tries to approve access using namespace as id
        ts::next_tx(&mut scenario, USER1);
        {
            let policy = ts::take_shared<AccessPolicy>(&scenario);
            let file = ts::take_shared<EncryptedFile>(&scenario);
            let attestation = ts::take_shared<TEEAttestation>(&scenario);
            
            // Use namespace as the id - this satisfies both prefix check and equality check
            let namespace = seal_manager::namespace(&policy);
            seal_manager::seal_approve(namespace, &file, &policy, &attestation, USER1);
            
            ts::return_shared(attestation);
            ts::return_shared(file);
            ts::return_shared(policy);
        };
        ts::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = seal_integration::seal_manager::EAccessDenied)]
    fun test_seal_approve_access_denied() {
        let mut scenario = setup_test();
        
        // Setup: Create policy with only USER1
        ts::next_tx(&mut scenario, ADMIN);
        {
            let allowed_addresses = vector[USER1];
            seal_manager::create_access_policy(allowed_addresses, ts::ctx(&mut scenario));
        };
        
        ts::next_tx(&mut scenario, ADMIN);
        {
            let policy = ts::take_shared<AccessPolicy>(&scenario);
            let namespace = seal_manager::namespace(&policy);
            seal_manager::save_encrypted_file(namespace, &policy, METADATA, ts::ctx(&mut scenario));
            ts::return_shared(policy);
        };
        
        ts::next_tx(&mut scenario, TEE);
        {
            let policy = ts::take_shared<AccessPolicy>(&scenario);
            let namespace = seal_manager::namespace(&policy);
            seal_manager::register_tee_attestation(ENCLAVE_ID, namespace, TEE, ts::ctx(&mut scenario));
            ts::return_shared(policy);
        };
        
        // Test: USER2 (not in policy) tries to approve access
        ts::next_tx(&mut scenario, USER2);
        {
            let policy = ts::take_shared<AccessPolicy>(&scenario);
            let file = ts::take_shared<EncryptedFile>(&scenario);
            let attestation = ts::take_shared<TEEAttestation>(&scenario);
            
            let namespace = seal_manager::namespace(&policy);
            seal_manager::seal_approve(namespace, &file, &policy, &attestation, USER2);
            
            ts::return_shared(attestation);
            ts::return_shared(file);
            ts::return_shared(policy);
        };
        ts::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = seal_integration::seal_manager::EBlobIdMismatch)]
    fun test_seal_approve_blob_id_mismatch() {
        let mut scenario = setup_test();
        
        // Setup: Create policy and file
        ts::next_tx(&mut scenario, ADMIN);
        {
            let allowed_addresses = vector[USER1];
            seal_manager::create_access_policy(allowed_addresses, ts::ctx(&mut scenario));
        };
        
        ts::next_tx(&mut scenario, ADMIN);
        {
            let policy = ts::take_shared<AccessPolicy>(&scenario);
            let namespace = seal_manager::namespace(&policy);
            seal_manager::save_encrypted_file(namespace, &policy, METADATA, ts::ctx(&mut scenario));
            ts::return_shared(policy);
        };
        
        // Create attestation with different blob ID
        ts::next_tx(&mut scenario, TEE);
        {
            seal_manager::register_tee_attestation(ENCLAVE_ID, b"different-blob", TEE, ts::ctx(&mut scenario));
        };
        
        // Test: Try to approve with mismatched blob ID
        ts::next_tx(&mut scenario, USER1);
        {
            let policy = ts::take_shared<AccessPolicy>(&scenario);
            let file = ts::take_shared<EncryptedFile>(&scenario);
            let attestation = ts::take_shared<TEEAttestation>(&scenario);
            
            let namespace = seal_manager::namespace(&policy);
            seal_manager::seal_approve(namespace, &file, &policy, &attestation, USER1);
            
            ts::return_shared(attestation);
            ts::return_shared(file);
            ts::return_shared(policy);
        };
        ts::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = seal_integration::seal_manager::EZeroAddressAttestation)]
    fun test_seal_approve_zero_address_attestation() {
        let mut scenario = setup_test();
        
        // Setup
        ts::next_tx(&mut scenario, ADMIN);
        {
            let allowed_addresses = vector[USER1];
            seal_manager::create_access_policy(allowed_addresses, ts::ctx(&mut scenario));
        };
        
        ts::next_tx(&mut scenario, ADMIN);
        {
            let policy = ts::take_shared<AccessPolicy>(&scenario);
            let namespace = seal_manager::namespace(&policy);
            seal_manager::save_encrypted_file(namespace, &policy, METADATA, ts::ctx(&mut scenario));
            ts::return_shared(policy);
        };
        
        // Create attestation with zero address
        ts::next_tx(&mut scenario, ZERO_ADDRESS);
        {
            let policy = ts::take_shared<AccessPolicy>(&scenario);
            let namespace = seal_manager::namespace(&policy);
            seal_manager::register_tee_attestation(ENCLAVE_ID, namespace, ZERO_ADDRESS, ts::ctx(&mut scenario));
            ts::return_shared(policy);
        };
        
        // Test: Try to approve with zero address attestation
        ts::next_tx(&mut scenario, USER1);
        {
            let policy = ts::take_shared<AccessPolicy>(&scenario);
            let file = ts::take_shared<EncryptedFile>(&scenario);
            let attestation = ts::take_shared<TEEAttestation>(&scenario);
            
            let namespace = seal_manager::namespace(&policy);
            seal_manager::seal_approve(namespace, &file, &policy, &attestation, USER1);
            
            ts::return_shared(attestation);
            ts::return_shared(file);
            ts::return_shared(policy);
        };
        ts::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = seal_integration::seal_manager::EInvalidId)]
    fun test_seal_approve_invalid_namespace() {
        let mut scenario = setup_test();
        
        // Setup
        ts::next_tx(&mut scenario, ADMIN);
        {
            let allowed_addresses = vector[USER1];
            seal_manager::create_access_policy(allowed_addresses, ts::ctx(&mut scenario));
        };
        
        ts::next_tx(&mut scenario, ADMIN);
        {
            let policy = ts::take_shared<AccessPolicy>(&scenario);
            let namespace = seal_manager::namespace(&policy);
            seal_manager::save_encrypted_file(namespace, &policy, METADATA, ts::ctx(&mut scenario));
            ts::return_shared(policy);
        };
        
        ts::next_tx(&mut scenario, TEE);
        {
            let policy = ts::take_shared<AccessPolicy>(&scenario);
            let namespace = seal_manager::namespace(&policy);
            seal_manager::register_tee_attestation(ENCLAVE_ID, namespace, TEE, ts::ctx(&mut scenario));
            ts::return_shared(policy);
        };
        
        // Test: Try to approve with wrong namespace (different blob_id)
        ts::next_tx(&mut scenario, USER1);
        {
            let policy = ts::take_shared<AccessPolicy>(&scenario);
            let file = ts::take_shared<EncryptedFile>(&scenario);
            let attestation = ts::take_shared<TEEAttestation>(&scenario);
            
            // Use different blob_id that doesn't have namespace prefix - should fail
            let wrong_id = b"wrong-blob-id";
            seal_manager::seal_approve(wrong_id, &file, &policy, &attestation, USER1);
            
            ts::return_shared(attestation);
            ts::return_shared(file);
            ts::return_shared(policy);
        };
        ts::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = seal_integration::seal_manager::EEmptyAllowedAddresses)]
    fun test_create_policy_empty_addresses() {
        let mut scenario = setup_test();
        
        ts::next_tx(&mut scenario, ADMIN);
        {
            let allowed_addresses = vector::empty<address>();
            seal_manager::create_access_policy(allowed_addresses, ts::ctx(&mut scenario));
        };
        ts::end(scenario);
    }
}
