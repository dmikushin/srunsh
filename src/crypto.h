#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace srunsh {

struct KeyPair {
    std::vector<uint8_t> priv_key;   // 32 bytes  (Ed25519 seed)
    std::vector<uint8_t> pub_key;    // 32 bytes
};

bool generate_keypair(KeyPair& kp);

// File format:  SRUNSH-ED25519-PRIVATE <base64>   (private key file also stores pubkey)
//               SRUNSH-ED25519-PUBLIC  <base64>
bool save_private_key(const std::string& path, const KeyPair& kp);
bool save_public_key (const std::string& path, const std::vector<uint8_t>& pub);
bool load_private_key(const std::string& path, KeyPair& kp);
bool load_public_key (const std::string& path, std::vector<uint8_t>& pub);

// authorized_keys — one "SRUNSH-ED25519-PUBLIC <base64>" per line
bool add_authorized_key(const std::string& path, const std::vector<uint8_t>& pub);
bool is_authorized     (const std::string& path, const std::vector<uint8_t>& pub);

// Ed25519 sign / verify
bool sign_data  (const KeyPair& kp, const uint8_t* data, size_t len,
                 std::vector<uint8_t>& sig);
bool verify_data(const std::vector<uint8_t>& pub, const uint8_t* data, size_t len,
                 const uint8_t* sig, size_t sig_len);

// CSPRNG
bool random_bytes(uint8_t* buf, size_t len);

// base64
std::string b64_encode(const uint8_t* data, size_t len);
bool        b64_decode(const std::string& in, std::vector<uint8_t>& out);

// ~/.srunsh  (created with 0700 if absent)
std::string srunsh_dir();

} // namespace srunsh
