#include "crypto.h"
#include <cstdio>

int main() {
    std::string dir       = srunsh::srunsh_dir();
    std::string priv_path = dir + "/id_ed25519";
    std::string pub_path  = dir + "/id_ed25519.pub";
    std::string auth_path = dir + "/authorized_keys";

    srunsh::KeyPair kp;
    if (!srunsh::generate_keypair(kp)) {
        fprintf(stderr, "Failed to generate Ed25519 key pair\n");
        return 1;
    }

    if (!srunsh::save_private_key(priv_path, kp)) {
        fprintf(stderr, "Failed to save private key to %s\n", priv_path.c_str());
        return 1;
    }
    if (!srunsh::save_public_key(pub_path, kp.pub_key)) {
        fprintf(stderr, "Failed to save public key to %s\n", pub_path.c_str());
        return 1;
    }
    if (!srunsh::add_authorized_key(auth_path, kp.pub_key)) {
        fprintf(stderr, "Failed to update %s\n", auth_path.c_str());
        return 1;
    }

    printf("Key pair generated:\n");
    printf("  Private key:  %s\n", priv_path.c_str());
    printf("  Public key:   %s\n", pub_path.c_str());
    printf("  Fingerprint:  %s\n",
           srunsh::b64_encode(kp.pub_key.data(), kp.pub_key.size()).c_str());
    printf("Public key added to %s\n", auth_path.c_str());
    return 0;
}
