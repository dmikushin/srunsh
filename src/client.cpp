// srunsh — SSH-like client that uses SLURM srun as transport.
//
// Usage:
//   srunsh [-L localport:host:remoteport]... [-S jobid] [-- [srun_opts...] [-- command...]]
//
// Examples:
//   srunsh -- --gres=gpu:4 -- htop
//   srunsh -L 11434:localhost:11434 -S 69984 -- --gres=gpu:4 -- htop
//   srunsh -S 69984

#include "protocol.h"
#include "crypto.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

namespace fs = std::filesystem;
using namespace srunsh;

// ---- types ----
struct PortForward {
    uint16_t    local_port;
    std::string remote_host;
    uint16_t    remote_port;
};

// ---- globals for signal handlers / cleanup ----
static volatile sig_atomic_t g_winch = 0;
static struct termios g_orig_termios;
static bool g_raw_mode = false;

static void handle_winch(int) { g_winch = 1; }

static void restore_terminal() {
    if (g_raw_mode) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_orig_termios);
        // Restore blocking mode so the parent shell is not confused.
        int fl = fcntl(STDIN_FILENO, F_GETFL, 0);
        fcntl(STDIN_FILENO, F_SETFL, fl & ~O_NONBLOCK);
        g_raw_mode = false;
    }
}

static void set_raw_mode() {
    tcgetattr(STDIN_FILENO, &g_orig_termios);
    struct termios raw = g_orig_termios;
    cfmakeraw(&raw);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    g_raw_mode = true;
    atexit(restore_terminal);
}

static void set_nonblock(int fd) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}

// ---- networking ----
static int create_listener(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(port);
    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0 ||
        listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }
    set_nonblock(fd);
    return fd;
}

// ---- deploy server binary ----
static std::string get_exe_dir() {
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return ".";
    buf[n] = '\0';
    return fs::path(buf).parent_path().string();
}

static std::string deploy_server() {
    std::string src     = get_exe_dir() + "/srunshd";
    std::string dst_dir = srunsh_dir()  + "/bin";
    std::string dst     = dst_dir       + "/srunshd";

    if (fs::exists(src)) {
        fs::create_directories(dst_dir);
        // Copy only when source is newer or destination is absent.
        if (!fs::exists(dst) ||
            fs::last_write_time(src) > fs::last_write_time(dst)) {
            std::error_code ec;
            fs::copy_file(src, dst, fs::copy_options::overwrite_existing, ec);
            if (ec)
                fprintf(stderr, "srunsh: warning: deploy failed: %s\n",
                        ec.message().c_str());
            else
                chmod(dst.c_str(), 0755);
        }
    } else if (!fs::exists(dst)) {
        fprintf(stderr,
                "srunsh: server binary not found (looked in %s and %s)\n",
                src.c_str(), dst.c_str());
        exit(1);
    }
    return dst;
}

// ---- argument parsing ----
static bool parse_forward(const char* spec, PortForward& fwd) {
    char host[256];
    if (sscanf(spec, "%hu:%255[^:]:%hu",
               &fwd.local_port, host, &fwd.remote_port) != 3)
        return false;
    fwd.remote_host = host;
    return true;
}

static void usage() {
    fprintf(stderr,
        "Usage: srunsh [options] [-- [srun_opts...] [-- command...]]\n"
        "\n"
        "Options:\n"
        "  -L lport:host:rport   Local port forwarding (repeatable)\n"
        "  -S jobid              Attach to existing SLURM job allocation\n"
        "  -h, --help            Show this help\n"
        "\n"
        "Everything between the first '--' and the second '--' is passed to srun.\n"
        "Everything after the second '--' is the remote command.\n"
        "\n"
        "Example:\n"
        "  srunsh -L 11434:localhost:11434 -S 69984 -- --gres=gpu:4 -- htop\n"
    );
}

// ---- authentication ----
static bool do_auth(int wr, int rd, RecvBuffer& rbuf) {
    // Load key
    KeyPair kp;
    if (!load_private_key(srunsh_dir() + "/id_ed25519", kp)) {
        fprintf(stderr, "srunsh: no key found — run srunsh-keygen first\n");
        return false;
    }

    // Receive AUTH_CHALLENGE (blocking on raw fd — server sends it first)
    Message msg;
    while (true) {
        ssize_t n = rbuf.feed(rd);
        if (n <= 0) { perror("srunsh: read challenge"); return false; }
        if (rbuf.parse(msg)) break;
    }
    if (msg.type != MSG_AUTH_CHALLENGE || msg.payload.size() != 32) {
        fprintf(stderr, "srunsh: bad handshake (type 0x%02x, %zu B)\n",
                msg.type, msg.payload.size());
        return false;
    }

    // Sign challenge
    std::vector<uint8_t> sig;
    if (!sign_data(kp, msg.payload.data(), msg.payload.size(), sig)) {
        fprintf(stderr, "srunsh: signing failed\n");
        return false;
    }

    // Send AUTH_RESPONSE  [32 B pubkey | 64 B sig]
    Packer p;
    p.raw(kp.pub_key);
    p.raw(sig);
    if (!send_msg(wr, make_msg(MSG_AUTH_RESPONSE, 0, p.finish())))
        return false;

    // Receive result
    while (true) {
        ssize_t n = rbuf.feed(rd);
        if (n <= 0) return false;
        if (rbuf.parse(msg)) break;
    }
    if (msg.type == MSG_AUTH_OK) return true;
    fprintf(stderr, "srunsh: authentication failed\n");
    return false;
}

// ---- main ----
int main(int argc, char* argv[]) {
    std::vector<PortForward>  forwards;
    std::string               job_id;

    // 1. Parse srunsh options (before first --)
    int i = 1;
    while (i < argc) {
        std::string a = argv[i];
        if (a == "--")     { ++i; break; }
        if (a == "-h" || a == "--help") { usage(); return 0; }
        if (a == "-L" && i + 1 < argc) {
            PortForward fwd;
            if (!parse_forward(argv[++i], fwd)) {
                fprintf(stderr, "srunsh: bad -L spec: %s\n", argv[i]);
                return 1;
            }
            forwards.push_back(fwd);
        } else if (a == "-S" && i + 1 < argc) {
            job_id = argv[++i];
        } else {
            fprintf(stderr, "srunsh: unknown option: %s\n", a.c_str());
            usage(); return 1;
        }
        ++i;
    }

    // 2. srun options (between first and second --)
    std::vector<std::string> srun_opts;
    while (i < argc) {
        std::string a = argv[i];
        if (a == "--") { ++i; break; }
        srun_opts.push_back(a);
        ++i;
    }

    // 3. Remote command (after second --)
    std::string remote_cmd;
    for (; i < argc; ++i) {
        if (!remote_cmd.empty()) remote_cmd += ' ';
        remote_cmd += argv[i];
    }

    // Deploy server
    std::string server_bin = deploy_server();

    // Build srun argv
    std::vector<std::string> cmd;
    cmd.emplace_back("srun");
    cmd.emplace_back("--unbuffered");   // critical: srun buffers stdout by default
    if (!job_id.empty()) {
        cmd.push_back("--jobid=" + job_id);
    }
    for (auto& o : srun_opts) cmd.push_back(o);
    cmd.push_back(server_bin);

    std::vector<char*> cargv;
    for (auto& s : cmd) cargv.push_back(const_cast<char*>(s.c_str()));
    cargv.push_back(nullptr);

    // Fork srun
    int to_child[2], from_child[2];
    if (pipe(to_child) < 0 || pipe(from_child) < 0) {
        perror("srunsh: pipe"); return 1;
    }

    pid_t srun_pid = fork();
    if (srun_pid < 0) { perror("srunsh: fork"); return 1; }

    if (srun_pid == 0) {
        close(to_child[1]);
        close(from_child[0]);
        dup2(to_child[0],   STDIN_FILENO);
        dup2(from_child[1], STDOUT_FILENO);
        close(to_child[0]);
        close(from_child[1]);
        execvp(cargv[0], cargv.data());
        perror("srunsh: exec srun");
        _exit(127);
    }

    close(to_child[0]);
    close(from_child[1]);
    int wr_fd = to_child[1];     // write → server
    int rd_fd = from_child[0];   // read  ← server

    // ---- handshake ----
    RecvBuffer rbuf;
    if (!do_auth(wr_fd, rd_fd, rbuf)) {
        close(wr_fd); close(rd_fd);
        kill(srun_pid, SIGTERM);
        waitpid(srun_pid, nullptr, 0);
        return 1;
    }

    // ---- send SHELL_REQ ----
    {
        struct winsize ws{};
        if (isatty(STDIN_FILENO))
            ioctl(STDIN_FILENO, TIOCGWINSZ, &ws);
        else
            ws = {24, 80, 0, 0};

        Packer p;
        p.u16(ws.ws_row);
        p.u16(ws.ws_col);
        p.str(remote_cmd);
        send_msg(wr_fd, make_msg(MSG_SHELL_REQ, 0, p.finish()));
    }

    // ---- set up port-forward listeners ----
    std::map<int, size_t> listener_idx;           // listener fd → fwd index
    for (size_t j = 0; j < forwards.size(); ++j) {
        int lfd = create_listener(forwards[j].local_port);
        if (lfd < 0) {
            fprintf(stderr, "srunsh: cannot listen on port %u\n",
                    forwards[j].local_port);
            continue;
        }
        listener_idx[lfd] = j;
        fprintf(stderr, "srunsh: forwarding 127.0.0.1:%u → %s:%u\n",
                forwards[j].local_port,
                forwards[j].remote_host.c_str(),
                forwards[j].remote_port);
    }

    // ---- enter raw mode & main loop ----
    if (isatty(STDIN_FILENO)) set_raw_mode();
    set_nonblock(rd_fd);
    set_nonblock(STDIN_FILENO);

    {
        struct sigaction sa{};
        sa.sa_handler = handle_winch;
        sigaction(SIGWINCH, &sa, nullptr);
    }
    signal(SIGPIPE, SIG_IGN);

    std::map<uint32_t, int> chan_fd;    // channel → socket
    std::map<int, uint32_t> fd_chan;    // socket  → channel
    uint32_t next_chan = 1;
    int  exit_code = 0;
    bool running   = true;

    while (running) {
        // Pending SIGWINCH?
        if (g_winch) {
            g_winch = 0;
            struct winsize ws{};
            ioctl(STDIN_FILENO, TIOCGWINSZ, &ws);
            Packer p;
            p.u16(ws.ws_row);
            p.u16(ws.ws_col);
            send_msg(wr_fd, make_msg(MSG_SHELL_RESIZE, 0, p.finish()));
        }

        // Build poll set
        std::vector<struct pollfd> pfds;
        pfds.push_back({rd_fd,        POLLIN, 0});
        pfds.push_back({STDIN_FILENO, POLLIN, 0});
        for (auto& [fd, _] : listener_idx)
            pfds.push_back({fd, POLLIN, 0});
        for (auto& [fd, _] : fd_chan)
            pfds.push_back({fd, POLLIN, 0});

        if (poll(pfds.data(), pfds.size(), 500) < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (auto& pfd : pfds) {
            if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR)))
                continue;

            // ---- data from server ----
            if (pfd.fd == rd_fd) {
                ssize_t n = rbuf.feed(rd_fd);
                if (n == 0)                   { running = false; break; }
                if (n < 0 && errno != EAGAIN) { running = false; break; }

                Message msg;
                while (rbuf.parse(msg)) {
                    switch (msg.type) {
                    case MSG_SHELL_DATA:
                        (void)!write(STDOUT_FILENO,
                                     msg.payload.data(), msg.payload.size());
                        break;

                    case MSG_SHELL_EXIT: {
                        Unpacker u(msg.payload);
                        exit_code = static_cast<int>(u.u32());
                        running = false;
                        break;
                    }

                    case MSG_FWD_ACCEPT:
                        break;   // channel ready — nothing to do

                    case MSG_FWD_REJECT:
                    case MSG_FWD_CLOSE:
                        if (chan_fd.count(msg.channel)) {
                            int cfd = chan_fd[msg.channel];
                            close(cfd);
                            fd_chan.erase(cfd);
                            chan_fd.erase(msg.channel);
                        }
                        break;

                    case MSG_FWD_DATA:
                        if (chan_fd.count(msg.channel))
                            (void)!write(chan_fd[msg.channel],
                                         msg.payload.data(),
                                         msg.payload.size());
                        break;
                    }
                    if (!running) break;
                }
            }

            // ---- terminal input ----
            else if (pfd.fd == STDIN_FILENO) {
                uint8_t buf[4096];
                ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
                if (n > 0)
                    send_msg(wr_fd,
                             make_msg(MSG_SHELL_DATA, 0, buf,
                                      static_cast<size_t>(n)));
            }

            // ---- new port-forward connection ----
            else if (listener_idx.count(pfd.fd)) {
                int conn = accept(pfd.fd, nullptr, nullptr);
                if (conn < 0) continue;
                set_nonblock(conn);
                uint32_t ch = next_chan++;
                size_t idx  = listener_idx[pfd.fd];

                Packer p;
                p.str(forwards[idx].remote_host);
                p.u16(forwards[idx].remote_port);
                send_msg(wr_fd, make_msg(MSG_FWD_OPEN, ch, p.finish()));

                chan_fd[ch]   = conn;
                fd_chan[conn] = ch;
            }

            // ---- data on forwarded socket ----
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
    restore_terminal();
    close(wr_fd);
    close(rd_fd);
    for (auto& [fd, _] : listener_idx) close(fd);
    for (auto& [_, fd]  : chan_fd)      close(fd);

    // Reap srun — give it a moment to shut down.
    int wst;
    if (waitpid(srun_pid, &wst, WNOHANG) == 0) {
        kill(srun_pid, SIGTERM);
        waitpid(srun_pid, &wst, 0);
    }
    return exit_code;
}
