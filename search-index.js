var searchIndex = JSON.parse('{\
"openmls_crypto":{"doc":"OpenMLS Crypto traits","t":[0,8,16,16,16,16,16,10,10,8,16,16,16,16,16,10,0,8,16,16,16,10,10,8,16,16,10,10,0,8,16,16,16,16,10,10,10,10,10,10,0,8,16,16,16,16,16,16,16,10,10,10,10,8,16,16,16,16,16,16,10,8,16,16,16,16,10,0,8,16,16,16,16,10,10,0,8,16,16,16,16,10,8,16,16,16,16,10,10,8,10,10],"n":["aead","Seal","KeyStoreType","KeyStoreIndex","Error","CiphertextTag","Tag","seal","seal_in_place","Open","KeyStoreType","KeyStoreIndex","Error","CiphertextTag","Plaintext","open","hash","Hash","StatefulHasher","Error","Digest","hash","hasher","Hasher","Error","Digest","update","finish","hkdf","HkdfDerive","KeyStoreType","KeyStoreIndex","Secret","Error","hkdf","extract","expand","hkdf_with_status","extract_with_status","expand_with_status","hpke","HpkeSeal","KeyStoreType","KeyStoreIndex","KemOutput","Ciphertext","Plaintext","PublicKey","Error","hpke_seal","hpke_seal_to_pk","hpke_seal_secret","hpke_seal_secret_to_pk","HpkeOpen","KeyStoreType","KeyStoreIndex","Plaintext","Ciphertext","KemInput","Error","hpke_open_with_sk","HpkeDerive","KeyStoreType","KeyStoreIndex","PublicKey","Error","derive_key_pair","key_generation","GenerateKeys","KeyStoreType","KeyStoreIndex","PublicKey","Error","new_secret","new_key_pair","signature","Sign","KeyStoreType","KeyStoreIndex","Signature","Error","sign","Verify","KeyStoreType","KeyStoreIndex","PublicKey","Error","verify","verify_with_pk","Supports","symmetric_key_types","asymmetric_key_types"],"q":["openmls_crypto","openmls_crypto::aead","","","","","","","","","","","","","","","openmls_crypto","openmls_crypto::hash","","","","","","","","","","","openmls_crypto","openmls_crypto::hkdf","","","","","","","","","","","openmls_crypto","openmls_crypto::hpke","","","","","","","","","","","","","","","","","","","","","","","","","","openmls_crypto","openmls_crypto::key_generation","","","","","","","openmls_crypto","openmls_crypto::signature","","","","","","","","","","","","","openmls_crypto","",""],"d":["","AEAD Seal","The key store type used for <code>Seal</code>.","The type of the key store id used, i.e. the type for …","The error type returned by [<code>Seal</code>].","The ciphertext and tag return type of [<code>Seal::seal()</code>].","The tag return type of [<code>Seal::seal_in_place()</code>].","Encrypt the <code>msg</code> with the given parameters and return the …","Encrypt the <code>msg</code> with the given parameters and return the …","AEAD Open","The key store type used for [<code>Open</code>].","The type of the key store id used, i.e. the type for …","The error type returned by [<code>Open</code>].","The ciphertext and tag input type of [<code>Open::open()</code>].","The plaintext return type of [<code>Open::open()</code>].","Decrypt the <code>cipher_text</code> with the given parameters and …","","Hashing","The return type of [<code>Hash::hasher()</code>], a stateful hasher.","The error type returned by [<code>Hash</code>].","The return type of the [<code>Hash::hash</code>] function.","Single-shot hash","Get a stateful hasher object for the streaming API.","Streaming API for hashing","The error type returned by [<code>Hasher</code>].","The return type of the [<code>Hasher::finish</code>] function.","Add the <code>data</code> byte slice to the hash state.","Finish the hash computation and return the result. This …","","HKDF","The key store type used for <code>Seal</code>.","The type of the key store id used, i.e. the type for …","The type of the secrets used in HKDF.","The error type returned by [<code>HkdfDerive</code>].","HKDF Compute HKDF on the input and store it with the <code>okm</code> …","HKDF extract Extract pre-key material from <code>ikm</code> and store …","HKDF expand The expanded secret is stored with the <code>okm</code> id.","HKDF Compute HKDF on the input and store it with the <code>okm</code> …","HKDF extract Extract pre-key material from <code>ikm</code> and store …","HKDF expand The expanded secret is stored with the <code>okm</code> id …","","HPKE Note that his trait only holds a very limited subset …","The key store type used for [<code>HpkeSeal</code>].","The type of the key store id used, i.e. the type for …","The type of the KEM output.","The type of the ciphertext output.","The type of the plaintext input.","The type of the public key input.","The error type returned by [<code>HpkeSeal</code>].","Encrypt the <code>payload</code> to the public key stored for <code>key_id</code>.","Encrypt the <code>payload</code> to the public <code>key</code>.","Encrypt the secret stored for <code>secret_id</code> to the public key …","Encrypt the secret stored for <code>secret_id</code> to the public <code>key</code>.","","The key store type used for [<code>HpkeOpen</code>].","The type of the key store id used, i.e. the type for …","The type of the plaintext output.","The type of the ciphertext input.","The type of the KEM input.","The error type returned by [<code>HpkeOpen</code>].","Open an HPKE <code>cipher_text</code> with the private key of the …","XXX: We really only need the KEM type here. But hpke-rs …","The key store type used for <code>Seal</code>.","The type of the key store id used, i.e. the type for …","The type of the public key output.","The error type returned by [<code>HpkeDerive</code>].","Derive a new HPKE keypair from the secret at <code>ikm_id</code>.","","Generate keys.","The key store type used for [<code>GenerateKeys</code>].","The type of the key store id used, i.e. the type for …","The type of the public key generated and returned.","The error type returned by [<code>GenerateKeys</code>].","","Generate a new key pair and return the […","","","The key store type used for [<code>Sign</code>].","The type of the key store id used, i.e. the type for …","The type of the signature produced by [<code>Sign::sign()</code>].","The error type returned by [<code>Sign</code>].","","","The key store type used for [<code>Sign</code>].","The type of the key store id used, i.e. the type for …","The type of the public key used to verify the signature.","The error type returned by [<code>Sign</code>].","","","Check whether the key store supports certain …","",""],"i":[0,0,1,1,1,1,1,1,1,0,2,2,2,2,2,2,0,0,3,3,3,3,3,0,4,4,4,4,0,0,5,5,5,5,5,5,5,5,5,5,0,0,6,6,6,6,6,6,6,6,6,6,6,0,7,7,7,7,7,7,7,0,8,8,8,8,8,0,0,9,9,9,9,9,9,0,0,10,10,10,10,10,0,11,11,11,11,11,11,0,12,12],"f":[null,null,null,null,null,null,null,[[["aeadtype",4]],["result",4]],[[["aeadtype",4]],["result",4]],null,null,null,null,null,null,[[["aeadtype",4]],["result",4]],null,null,null,null,null,[[["hashtype",4]],["result",4]],[[["hashtype",4]],["result",4]],null,null,null,[[],["result",4]],[[],["result",4]],null,null,null,null,null,null,[[["usize",15],["hashtype",4]],["result",4]],[[["hashtype",4]],["result",4]],[[["usize",15],["hashtype",4]],["result",4]],[[["usize",15],["hashtype",4],["status",4]],["result",4]],[[["hashtype",4],["status",4]],["result",4]],[[["usize",15],["hashtype",4],["status",4]],["result",4]],null,null,null,null,null,null,null,null,null,[[["aeadtype",4],["kdftype",4]],["result",4]],[[["aeadtype",4],["kdftype",4]],["result",4]],[[["aeadtype",4],["kdftype",4]],["result",4]],[[["aeadtype",4],["kdftype",4]],["result",4]],null,null,null,null,null,null,null,[[["aeadtype",4],["kdftype",4]],["result",4]],null,null,null,null,null,[[["kdftype",4],["aeadtype",4],["kemtype",4]],["result",4]],null,null,null,null,null,null,[[["symmetrickeytype",4],["status",4]],["result",4]],[[["asymmetrickeytype",4],["status",4]],["result",4]],null,null,null,null,null,null,[[],["result",4]],null,null,null,null,null,[[],["result",4]],[[],["result",4]],null,[[],[["vec",3],["symmetrickeytype",4]]],[[],[["asymmetrickeytype",4],["vec",3]]]],"p":[[8,"Seal"],[8,"Open"],[8,"Hash"],[8,"Hasher"],[8,"HkdfDerive"],[8,"HpkeSeal"],[8,"HpkeOpen"],[8,"HpkeDerive"],[8,"GenerateKeys"],[8,"Sign"],[8,"Verify"],[8,"Supports"]]}\
}');
initSearch(searchIndex);