// srunshd — server half of srunsh.
//
// Launched by srunsh via srun.  Communicates with the client through
// stdin (read) / stdout (write) — the pipe that srun sets up.

#include "protocol.h"
#include "crypto.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <utmp.h>

using namespace srunsh;

static volatile sig_atomic_t g_term = 0;
static void handle_term(int) { g_term = 1; }

static void set_nonblock(int fd) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}

static int connect_to(const std::string& host, uint16_t port) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char ps[16];
    snprintf(ps, sizeof(ps), "%u", port);
    if (getaddrinfo(host.c_str(), ps, &hints, &res) != 0) return -1;

    int fd = -1;
    for (auto* rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

// ---- authentication ----
static bool do_auth(int wr, int rd, RecvBuffer& rbuf) {
    // Send challenge
    uint8_t challenge[32];
    if (!random_bytes(challenge, 32)) return false;
    if (!send_msg(wr, make_msg(MSG_AUTH_CHALLENGE, 0, challenge, 32)))
        return false;

    // Receive response
    Message msg;
    while (true) {
        ssize_t n = rbuf.feed(rd);
        if (n <= 0) return false;
        if (rbuf.parse(msg)) break;
    }
    if (msg.type != MSG_AUTH_RESPONSE || msg.payload.size() < 96) {
        send_msg(wr, make_msg(MSG_AUTH_FAIL, 0));
        return false;
    }

    std::vector<uint8_t> pub(msg.payload.begin(), msg.payload.begin() + 32);
    const uint8_t* sig     = msg.payload.data() + 32;
    size_t         sig_len = msg.payload.size() - 32;

    std::string auth_path = srunsh_dir() + "/authorized_keys";
    if (!is_authorized(auth_path, pub) ||
        !verify_data(pub, challenge, 32, sig, sig_len)) {
        send_msg(wr, make_msg(MSG_AUTH_FAIL, 0));
        return false;
    }

    send_msg(wr, make_msg(MSG_AUTH_OK, 0));
    return true;
}

// ---- entry point ----
int main() {
    signal(SIGPIPE, SIG_IGN);
    {
        struct sigaction sa{};
        sa.sa_handler = handle_term;
        sigaction(SIGTERM, &sa, nullptr);
        sigaction(SIGINT,  &sa, nullptr);
    }

    int rd_fd = STDIN_FILENO;    // read  ← client
    int wr_fd = STDOUT_FILENO;   // write → client

    // Redirect our own stderr to a log (so stray writes don't break the pipe).
    // srun keeps a separate channel for stderr, so this is optional.

    // ---- auth ----
    RecvBuffer rbuf;
    if (!do_auth(wr_fd, rd_fd, rbuf))
        return 1;

    // ---- receive SHELL_REQ ----
    Message msg;
    while (true) {
        ssize_t n = rbuf.feed(rd_fd);
        if (n <= 0) return 1;
        if (rbuf.parse(msg)) break;
    }
    if (msg.type != MSG_SHELL_REQ) return 1;

    Unpacker u(msg.payload);
    uint16_t    rows    = u.u16();
    uint16_t    cols    = u.u16();
    std::string command = u.str();
    if (!u.ok()) return 1;

    // ---- allocate PTY + fork ----
    struct winsize ws{};
    ws.ws_row = rows;
    ws.ws_col = cols;

    int   master_fd = -1;
    pid_t child     = forkpty(&master_fd, nullptr, nullptr, &ws);
    if (child < 0) { perror("srunshd: forkpty"); return 1; }

    if (child == 0) {
        // ---- child: exec shell / command ----
        setenv("TERM", "xterm-256color", 1);
        if (command.empty()) {
            const char* sh = getenv("SHELL");
            if (!sh) sh = "/bin/bash";
            execlp(sh, sh, "-l", nullptr);
        } else {
            execlp("/bin/sh", "sh", "-c", command.c_str(), nullptr);
        }
        perror("srunshd: exec");
        _exit(127);
    }

    // ---- parent: multiplex ----
    set_nonblock(rd_fd);
    set_nonblock(master_fd);

    std::map<uint32_t, int> chan_fd;
    std::map<int, uint32_t> fd_chan;
    bool running = true;

    while (running && !g_term) {
        // Has the child exited?
        int wst;
        pid_t w = waitpid(child, &wst, WNOHANG);
        if (w > 0) {
            // Drain remaining PTY output.
            uint8_t buf[4096];
            for (;;) {
                ssize_t n = read(master_fd, buf, sizeof(buf));
                if (n <= 0) break;
                send_msg(wr_fd,
                         make_msg(MSG_SHELL_DATA, 0, buf,
                                  static_cast<size_t>(n)));
            }
            int code = WIFEXITED(wst) ? WEXITSTATUS(wst)
                                      : 128 + WTERMSIG(wst);
            Packer p;
            p.u32(static_cast<uint32_t>(code));
            send_msg(wr_fd, make_msg(MSG_SHELL_EXIT, 0, p.finish()));
            running = false;
            break;
        }

        // Build poll set
        std::vector<struct pollfd> pfds;
        pfds.push_back({rd_fd,     POLLIN, 0});
        pfds.push_back({master_fd, POLLIN, 0});
        for (auto& [fd, _] : fd_chan)
            pfds.push_back({fd, POLLIN, 0});

        if (poll(pfds.data(), pfds.size(), 200) < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (auto& pfd : pfds) {
            if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR)))
                continue;

            // ---- messages from client ----
            if (pfd.fd == rd_fd) {
                ssize_t n = rbuf.feed(rd_fd);
                if (n == 0)                   { running = false; break; }
                if (n < 0 && errno != EAGAIN) { running = false; break; }

                Message m;
                while (rbuf.parse(m)) {
                    switch (m.type) {
                    case MSG_SHELL_DATA:
                        (void)!write(master_fd,
                                     m.payload.data(), m.payload.size());
                        break;

                    case MSG_SHELL_RESIZE: {
                        Unpacker ru(m.payload);
                        struct winsize nws{};
                        nws.ws_row = ru.u16();
                        nws.ws_col = ru.u16();
                        ioctl(master_fd, TIOCSWINSZ, &nws);
                        break;
                    }

                    case MSG_FWD_OPEN: {
                        Unpacker fu(m.payload);
                        std::string host = fu.str();
                        uint16_t    port = fu.u16();
                        int conn = connect_to(host, port);
                        if (conn >= 0) {
                            set_nonblock(conn);
                            chan_fd[m.channel] = conn;
                            fd_chan[conn]      = m.channel;
                            send_msg(wr_fd,
                                     make_msg(MSG_FWD_ACCEPT, m.channel));
                        } else {
                            send_msg(wr_fd,
                                     make_msg(MSG_FWD_REJECT, m.channel));
                        }
                        break;
                    }

                    case MSG_FWD_DATA:
                        if (chan_fd.count(m.channel))
                            (void)!write(chan_fd[m.channel],
                                         m.payload.data(), m.payload.size());
                        break;

                    case MSG_FWD_CLOSE:
                        if (chan_fd.count(m.channel)) {
                            int cfd = chan_fd[m.channel];
                            close(cfd);
                            fd_chan.erase(cfd);
                            chan_fd.erase(m.channel);
                        }
                        break;
                    }
                }
            }

            // ---- PTY output ----
            else if (pfd.fd == master_fd) {
                if (pfd.revents & POLLIN) {
                    uint8_t buf[4096];
                    ssize_t n = read(master_fd, buf, sizeof(buf));
                    if (n > 0)
                        send_msg(wr_fd,
                                 make_msg(MSG_SHELL_DATA, 0, buf,
                                          static_cast<size_t>(n)));
                }
                // POLLHUP on master → child likely exited, next waitpid picks it up.
            }

            // ---- forwarded socket data ----
            else if (fd_chan.count(pfd.fd)) {
                uint32_t ch = fd_chan[pfd.fd];
                uint8_t buf[8192];
                ssize_t n = read(pfd.fd, buf, sizeof(buf));
                if (n > 0) {
                    send_msg(wr_fd,
                             make_msg(MSG_FWD_DATA, ch, buf,
                                      static_cast<size_t>(n)));
                } else {
                    send_msg(wr_fd, make_msg(MSG_FWD_CLOSE, ch));
                    close(pfd.fd);
                    fd_chan.erase(pfd.fd);
                    chan_fd.erase(ch);
                }
            }
        }
    }

    // ---- cleanup ----
    close(master_fd);
    for (auto& [_, fd] : chan_fd) close(fd);
    kill(child, SIGHUP);
    waitpid(child, nullptr, 0);
    return 0;
}
