#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>

namespace srunsh {

// ---- message types ----
enum : uint8_t {
    MSG_AUTH_CHALLENGE = 0x01,
    MSG_AUTH_RESPONSE  = 0x02,
    MSG_AUTH_OK        = 0x03,
    MSG_AUTH_FAIL      = 0x04,

    MSG_SHELL_REQ      = 0x10,
    MSG_SHELL_DATA     = 0x11,
    MSG_SHELL_RESIZE   = 0x12,
    MSG_SHELL_EXIT     = 0x13,
    MSG_SHELL_CLOSE    = 0x14,  // Client → Server: kill session on this channel

    MSG_FWD_OPEN       = 0x20,
    MSG_FWD_ACCEPT     = 0x21,
    MSG_FWD_REJECT     = 0x22,
    MSG_FWD_DATA       = 0x23,
    MSG_FWD_CLOSE      = 0x24,
};

// Wire format:
//   [4 B big-endian body_len] [1 B type] [4 B channel] [payload ...]
//   body_len = 1 + 4 + payload.size()
struct Message {
    uint8_t  type    = 0;
    uint32_t channel = 0;
    std::vector<uint8_t> payload;
};

// Blocking send of one complete message. Returns false on I/O error.
bool send_msg(int fd, const Message& msg);

// ---- receive buffer (safe with non-blocking fds) ----
class RecvBuffer {
public:
    // Read whatever is available from fd into internal buffer.
    // Returns bytes read, 0 on EOF, -1 on error (check errno for EAGAIN).
    ssize_t feed(int fd);

    // Try to extract one complete message. Returns true on success.
    bool parse(Message& msg);

    bool empty() const { return rpos_ >= wpos_; }

private:
    std::vector<uint8_t> buf_ = std::vector<uint8_t>(16384);
    size_t rpos_ = 0;
    size_t wpos_ = 0;

    void compact();
    void ensure(size_t need);
};

// ---- helpers: pack data into a byte vector ----
class Packer {
public:
    void u8(uint8_t v)  { buf_.push_back(v); }
    void u16(uint16_t v){ buf_.push_back(v >> 8); buf_.push_back(v & 0xFF); }
    void u32(uint32_t v){
        buf_.push_back((v >> 24) & 0xFF);
        buf_.push_back((v >> 16) & 0xFF);
        buf_.push_back((v >>  8) & 0xFF);
        buf_.push_back( v        & 0xFF);
    }
    void str(const std::string& s) {
        u32(static_cast<uint32_t>(s.size()));
        buf_.insert(buf_.end(), s.begin(), s.end());
    }
    void raw(const uint8_t* d, size_t n) { buf_.insert(buf_.end(), d, d + n); }
    void raw(const std::vector<uint8_t>& v) { buf_.insert(buf_.end(), v.begin(), v.end()); }

    std::vector<uint8_t> finish() { return std::move(buf_); }

private:
    std::vector<uint8_t> buf_;
};

// ---- helpers: unpack data from a byte range ----
class Unpacker {
public:
    Unpacker(const uint8_t* d, size_t n) : ptr_(d), end_(d + n) {}
    explicit Unpacker(const std::vector<uint8_t>& v)
        : ptr_(v.data()), end_(v.data() + v.size()) {}

    uint8_t  u8()  { if (ptr_+1 > end_) { ok_=false; return 0; } return *ptr_++; }
    uint16_t u16() {
        if (ptr_+2 > end_) { ok_=false; return 0; }
        uint16_t v = (uint16_t(ptr_[0])<<8)|ptr_[1]; ptr_+=2; return v;
    }
    uint32_t u32() {
        if (ptr_+4 > end_) { ok_=false; return 0; }
        uint32_t v = (uint32_t(ptr_[0])<<24)|(uint32_t(ptr_[1])<<16)|
                     (uint32_t(ptr_[2])<<8)|ptr_[3];
        ptr_+=4; return v;
    }
    std::string str() {
        uint32_t len = u32();
        if (!ok_ || ptr_+len > end_) { ok_=false; return {}; }
        std::string s(reinterpret_cast<const char*>(ptr_), len);
        ptr_ += len; return s;
    }
    std::vector<uint8_t> bytes(size_t n) {
        if (ptr_+n > end_) { ok_=false; return {}; }
        std::vector<uint8_t> v(ptr_, ptr_+n); ptr_+=n; return v;
    }

    size_t remaining() const { return static_cast<size_t>(end_ - ptr_); }
    bool ok() const { return ok_; }

private:
    const uint8_t* ptr_;
    const uint8_t* end_;
    bool ok_ = true;
};

// ---- convenience constructors ----
inline Message make_msg(uint8_t type, uint32_t ch = 0) {
    return {type, ch, {}};
}
inline Message make_msg(uint8_t type, uint32_t ch,
                        const void* data, size_t len) {
    Message m{type, ch, {}};
    auto p = static_cast<const uint8_t*>(data);
    m.payload.assign(p, p + len);
    return m;
}
inline Message make_msg(uint8_t type, uint32_t ch,
                        std::vector<uint8_t> payload) {
    return {type, ch, std::move(payload)};
}

} // namespace srunsh
