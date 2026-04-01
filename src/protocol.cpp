#include "protocol.h"
#include <cerrno>

namespace srunsh {

// ---- blocking helpers ----
static bool full_write(int fd, const void* buf, size_t count) {
    auto p = static_cast<const uint8_t*>(buf);
    while (count > 0) {
        ssize_t n = ::write(fd, p, count);
        if (n < 0) { if (errno == EINTR) continue; return false; }
        if (n == 0) return false;
        p     += n;
        count -= static_cast<size_t>(n);
    }
    return true;
}

bool send_msg(int fd, const Message& msg) {
    uint32_t body_len = 1 + 4 + static_cast<uint32_t>(msg.payload.size());
    uint8_t hdr[9];
    hdr[0] = (body_len >> 24) & 0xFF;
    hdr[1] = (body_len >> 16) & 0xFF;
    hdr[2] = (body_len >>  8) & 0xFF;
    hdr[3] =  body_len        & 0xFF;
    hdr[4] = msg.type;
    hdr[5] = (msg.channel >> 24) & 0xFF;
    hdr[6] = (msg.channel >> 16) & 0xFF;
    hdr[7] = (msg.channel >>  8) & 0xFF;
    hdr[8] =  msg.channel        & 0xFF;
    if (!full_write(fd, hdr, 9)) return false;
    if (!msg.payload.empty())
        if (!full_write(fd, msg.payload.data(), msg.payload.size())) return false;
    return true;
}

// ---- RecvBuffer ----
void RecvBuffer::compact() {
    if (rpos_ == 0) return;
    if (rpos_ < wpos_)
        std::memmove(buf_.data(), buf_.data() + rpos_, wpos_ - rpos_);
    wpos_ -= rpos_;
    rpos_  = 0;
}

void RecvBuffer::ensure(size_t need) {
    if (buf_.size() - wpos_ >= need) return;
    compact();
    if (buf_.size() - wpos_ < need)
        buf_.resize(wpos_ + need);
}

ssize_t RecvBuffer::feed(int fd) {
    ensure(8192);
    ssize_t n = ::read(fd, buf_.data() + wpos_, buf_.size() - wpos_);
    if (n > 0) wpos_ += static_cast<size_t>(n);
    return n;
}

bool RecvBuffer::parse(Message& msg) {
    size_t have = wpos_ - rpos_;
    if (have < 4) return false;

    const uint8_t* p = buf_.data() + rpos_;
    uint32_t body_len = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
                        (uint32_t(p[2]) <<  8) |  p[3];

    // sanity: body must hold at least type(1) + channel(4); cap at 16 MiB
    if (body_len < 5 || body_len > 16u * 1024 * 1024) return false;
    if (have < 4 + body_len) return false;

    msg.type    = p[4];
    msg.channel = (uint32_t(p[5]) << 24) | (uint32_t(p[6]) << 16) |
                  (uint32_t(p[7]) <<  8) |  p[8];

    size_t payload_len = body_len - 5;
    msg.payload.assign(p + 9, p + 9 + payload_len);

    rpos_ += 4 + body_len;
    return true;
}

} // namespace srunsh
