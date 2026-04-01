// srunshd — server half of srunsh.
//
// Launched once per job via srun.  Supports multiple shell sessions
// multiplexed over the single stdin/stdout pipe from srun.

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
    uint8_t challenge[32];
    if (!random_bytes(challenge, 32)) return false;
    if (!send_msg(wr, make_msg(MSG_AUTH_CHALLENGE, 0, challenge, 32)))
        return false;

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

// ---- shell session ----
struct ShellSession {
    int   master_fd;
    pid_t child;
};

static bool create_shell(uint32_t channel, uint16_t rows, uint16_t cols,
                         const std::string& command,
                         std::map<uint32_t, ShellSession>& shells,
                         std::map<int, uint32_t>& mfd_chan) {
    struct winsize ws{};
    ws.ws_row = rows;
    ws.ws_col = cols;

    int   mfd   = -1;
    pid_t child = forkpty(&mfd, nullptr, nullptr, &ws);
    if (child < 0) return false;

    if (child == 0) {
        setenv("TERM", "xterm-256color", 1);
        if (command.empty()) {
            const char* sh = getenv("SHELL");
            if (!sh) sh = "/bin/bash";
            execlp(sh, sh, "-l", nullptr);
        } else {
            execlp("/bin/sh", "sh", "-c", command.c_str(), nullptr);
        }
        _exit(127);
    }

    set_nonblock(mfd);
    shells[channel]  = {mfd, child};
    mfd_chan[mfd]    = channel;
    return true;
}

static void kill_shell(uint32_t ch,
                       std::map<uint32_t, ShellSession>& shells,
                       std::map<int, uint32_t>& mfd_chan) {
    auto it = shells.find(ch);
    if (it == shells.end()) return;
    close(it->second.master_fd);
    kill(it->second.child, SIGHUP);
    mfd_chan.erase(it->second.master_fd);
    shells.erase(it);
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

    int rd_fd = STDIN_FILENO;
    int wr_fd = STDOUT_FILENO;

    RecvBuffer rbuf;
    if (!do_auth(wr_fd, rd_fd, rbuf))
        return 1;

    set_nonblock(rd_fd);

    std::map<uint32_t, ShellSession> shells;
    std::map<int, uint32_t> mfd_chan;      // master_fd → channel
    std::map<uint32_t, int> fwd_fd;        // fwd channel → socket
    std::map<int, uint32_t> fd_fwd;        // fwd socket → channel
    bool running   = true;
    bool pipe_open = true;

    while (running && !g_term) {
        // ---- reap exited children ----
        int wst;
        pid_t w;
        while ((w = waitpid(-1, &wst, WNOHANG)) > 0) {
            for (auto it = shells.begin(); it != shells.end(); ++it) {
                if (it->second.child != w) continue;
                uint32_t ch = it->first;
                int mfd     = it->second.master_fd;

                // drain remaining PTY output
                uint8_t buf[4096];
                for (;;) {
                    ssize_t n = read(mfd, buf, sizeof(buf));
                    if (n <= 0) break;
                    send_msg(wr_fd, make_msg(MSG_SHELL_DATA, ch, buf,
                                             static_cast<size_t>(n)));
                }
                int code = WIFEXITED(wst) ? WEXITSTATUS(wst)
                                          : 128 + WTERMSIG(wst);
                Packer p; p.u32(static_cast<uint32_t>(code));
                send_msg(wr_fd, make_msg(MSG_SHELL_EXIT, ch, p.finish()));

                close(mfd);
                mfd_chan.erase(mfd);
                shells.erase(it);
                break;
            }
        }

        // exit when pipe closed and nothing left to serve
        if (!pipe_open && shells.empty() && fwd_fd.empty())
            break;

        // ---- process buffered messages ----
        {
            Message m;
            while (rbuf.parse(m)) {
                switch (m.type) {
                case MSG_SHELL_REQ: {
                    Unpacker u(m.payload);
                    uint16_t rows = u.u16(), cols = u.u16();
                    std::string cmd = u.str();
                    if (u.ok())
                        create_shell(m.channel, rows, cols, cmd,
                                     shells, mfd_chan);
                    break;
                }
                case MSG_SHELL_DATA:
                    if (shells.count(m.channel))
                        (void)!write(shells[m.channel].master_fd,
                                     m.payload.data(), m.payload.size());
                    break;
                case MSG_SHELL_RESIZE:
                    if (shells.count(m.channel)) {
                        Unpacker ru(m.payload);
                        struct winsize nws{};
                        nws.ws_row = ru.u16();
                        nws.ws_col = ru.u16();
                        ioctl(shells[m.channel].master_fd, TIOCSWINSZ, &nws);
                    }
                    break;
                case MSG_SHELL_CLOSE:
                    kill_shell(m.channel, shells, mfd_chan);
                    break;

                case MSG_FWD_OPEN: {
                    Unpacker fu(m.payload);
                    std::string host = fu.str();
                    uint16_t port    = fu.u16();
                    int conn = connect_to(host, port);
                    if (conn >= 0) {
                        set_nonblock(conn);
                        fwd_fd[m.channel] = conn;
                        fd_fwd[conn]      = m.channel;
                        send_msg(wr_fd, make_msg(MSG_FWD_ACCEPT, m.channel));
                    } else {
                        send_msg(wr_fd, make_msg(MSG_FWD_REJECT, m.channel));
                    }
                    break;
                }
                case MSG_FWD_DATA:
                    if (fwd_fd.count(m.channel))
                        (void)!write(fwd_fd[m.channel],
                                     m.payload.data(), m.payload.size());
                    break;
                case MSG_FWD_CLOSE:
                    if (fwd_fd.count(m.channel)) {
                        int cfd = fwd_fd[m.channel];
                        close(cfd);
                        fd_fwd.erase(cfd);
                        fwd_fd.erase(m.channel);
                    }
                    break;
                }
            }
        }

        // ---- build poll set ----
        std::vector<struct pollfd> pfds;
        if (pipe_open)
            pfds.push_back({rd_fd, POLLIN, 0});
        for (auto& [mfd, _] : mfd_chan)
            pfds.push_back({mfd, POLLIN, 0});
        for (auto& [fd, _] : fd_fwd)
            pfds.push_back({fd, POLLIN, 0});

        if (pfds.empty()) break;

        if (poll(pfds.data(), pfds.size(), 200) < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (auto& pfd : pfds) {
            if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR)))
                continue;

            // ---- client pipe ----
            if (pfd.fd == rd_fd) {
                ssize_t n = rbuf.feed(rd_fd);
                if (n == 0)                   { pipe_open = false; }
                if (n < 0 && errno != EAGAIN) { pipe_open = false; }
                // messages processed next iteration
            }

            // ---- PTY output ----
            else if (mfd_chan.count(pfd.fd)) {
                if (pfd.revents & POLLIN) {
                    uint32_t ch = mfd_chan[pfd.fd];
                    uint8_t buf[4096];
                    ssize_t n = read(pfd.fd, buf, sizeof(buf));
                    if (n > 0)
                        send_msg(wr_fd, make_msg(MSG_SHELL_DATA, ch, buf,
                                                 static_cast<size_t>(n)));
                }
            }

            // ---- forwarded socket ----
            else if (fd_fwd.count(pfd.fd)) {
                uint32_t ch = fd_fwd[pfd.fd];
                uint8_t buf[8192];
                ssize_t n = read(pfd.fd, buf, sizeof(buf));
                if (n > 0) {
                    send_msg(wr_fd, make_msg(MSG_FWD_DATA, ch, buf,
                                             static_cast<size_t>(n)));
                } else {
                    send_msg(wr_fd, make_msg(MSG_FWD_CLOSE, ch));
                    close(pfd.fd);
                    fd_fwd.erase(pfd.fd);
                    fwd_fd.erase(ch);
                }
            }
        }
    }

    // ---- cleanup ----
    for (auto& [_, s] : shells) {
        close(s.master_fd);
        kill(s.child, SIGHUP);
    }
    for (auto& [_, fd] : fwd_fd) close(fd);
    while (waitpid(-1, nullptr, 0) > 0) {}
    return 0;
}
