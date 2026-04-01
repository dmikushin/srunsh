#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>

namespace fs = std::filesystem;

namespace srunsh {

// ---- directory ----
std::string srunsh_dir() {
    const char* home = std::getenv("HOME");
    if (!home) home = "/tmp";
    std::string dir = std::string(home) + "/.srunsh";
    fs::create_directories(dir);
    chmod(dir.c_str(), 0700);
    return dir;
}

// ---- CSPRNG ----
bool random_bytes(uint8_t* buf, size_t len) {
    return RAND_bytes(buf, static_cast<int>(len)) == 1;
}

// ---- base64 ----
std::string b64_encode(const uint8_t* data, size_t len) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data, static_cast<int>(len));
    BIO_flush(b64);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string result(bptr->data, bptr->length);
    BIO_free_all(b64);
    return result;
}

bool b64_decode(const std::string& in, std::vector<uint8_t>& out) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(in.data(), static_cast<int>(in.size()));
    mem = BIO_push(b64, mem);
    BIO_set_flags(mem, BIO_FLAGS_BASE64_NO_NL);
    out.resize(in.size());
    int n = BIO_read(mem, out.data(), static_cast<int>(out.size()));
    BIO_free_all(mem);
    if (n < 0) return false;
    out.resize(static_cast<size_t>(n));
    return true;
}

// ---- key generation ----
bool generate_keypair(KeyPair& kp) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx) return false;
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return false; }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { EVP_PKEY_CTX_free(ctx); return false; }
    EVP_PKEY_CTX_free(ctx);

    size_t priv_len = 32, pub_len = 32;
    kp.priv_key.resize(32);
    kp.pub_key.resize(32);
    EVP_PKEY_get_raw_private_key(pkey, kp.priv_key.data(), &priv_len);
    EVP_PKEY_get_raw_public_key (pkey, kp.pub_key.data(),  &pub_len);
    EVP_PKEY_free(pkey);
    return true;
}

// ---- key I/O ----
bool save_private_key(const std::string& path, const KeyPair& kp) {
    std::ofstream f(path, std::ios::trunc);
    if (!f) return false;
    f << "SRUNSH-ED25519-PRIVATE " << b64_encode(kp.priv_key.data(), kp.priv_key.size()) << "\n";
    f << "SRUNSH-ED25519-PUBLIC "  << b64_encode(kp.pub_key.data(),  kp.pub_key.size())  << "\n";
    f.close();
    chmod(path.c_str(), 0600);
    return true;
}

bool save_public_key(const std::string& path, const std::vector<uint8_t>& pub) {
    std::ofstream f(path, std::ios::trunc);
    if (!f) return false;
    f << "SRUNSH-ED25519-PUBLIC " << b64_encode(pub.data(), pub.size()) << "\n";
    f.close();
    chmod(path.c_str(), 0644);
    return true;
}

bool load_private_key(const std::string& path, KeyPair& kp) {
    std::ifstream f(path);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("SRUNSH-ED25519-PRIVATE ", 0) == 0)
            { if (!b64_decode(line.substr(23), kp.priv_key)) return false; }
        else if (line.rfind("SRUNSH-ED25519-PUBLIC ", 0) == 0)
            { if (!b64_decode(line.substr(22), kp.pub_key))  return false; }
    }
    return kp.priv_key.size() == 32 && kp.pub_key.size() == 32;
}

bool load_public_key(const std::string& path, std::vector<uint8_t>& pub) {
    std::ifstream f(path);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("SRUNSH-ED25519-PUBLIC ", 0) == 0) {
            if (!b64_decode(line.substr(22), pub)) return false;
            return pub.size() == 32;
        }
    }
    return false;
}

// ---- authorized keys ----
bool add_authorized_key(const std::string& path, const std::vector<uint8_t>& pub) {
    if (is_authorized(path, pub)) return true;
    std::ofstream f(path, std::ios::app);
    if (!f) return false;
    f << "SRUNSH-ED25519-PUBLIC " << b64_encode(pub.data(), pub.size()) << "\n";
    f.close();
    chmod(path.c_str(), 0600);
    return true;
}

bool is_authorized(const std::string& path, const std::vector<uint8_t>& pub) {
    std::ifstream f(path);
    if (!f) return false;
    std::string target = "SRUNSH-ED25519-PUBLIC " + b64_encode(pub.data(), pub.size());
    std::string line;
    while (std::getline(f, line))
        if (line == target) return true;
    return false;
}

// ---- Ed25519 sign ----
bool sign_data(const KeyPair& kp, const uint8_t* data, size_t len,
               std::vector<uint8_t>& sig) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, kp.priv_key.data(), kp.priv_key.size());
    if (!pkey) return false;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) { EVP_PKEY_free(pkey); return false; }

    bool ok = false;
    if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey) > 0) {
        size_t sig_len = 0;
        if (EVP_DigestSign(mdctx, nullptr, &sig_len, data, len) > 0) {
            sig.resize(sig_len);
            if (EVP_DigestSign(mdctx, sig.data(), &sig_len, data, len) > 0) {
                sig.resize(sig_len);
                ok = true;
            }
        }
    }
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return ok;
}

// ---- Ed25519 verify ----
bool verify_data(const std::vector<uint8_t>& pub, const uint8_t* data, size_t len,
                 const uint8_t* sig, size_t sig_len) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, pub.data(), pub.size());
    if (!pkey) return false;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) { EVP_PKEY_free(pkey); return false; }

    bool ok = false;
    if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey) > 0)
        ok = (EVP_DigestVerify(mdctx, sig, sig_len, data, len) == 1);

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return ok;
}

} // namespace srunsh
