// srunsh — SSH-like client over SLURM srun with session multiplexing.
//
// First invocation becomes the ControlMaster: launches srun, creates a
// local Unix socket.  Subsequent invocations connect to the master and
// get their own shell session — all over the same srun step, so all
// sessions share the full GPU allocation.
//
// Usage:
//   srunsh [-L lport:host:rport]... [-S jobid] [-- [srun_opts...] [-- cmd...]]

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
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

namespace fs = std::filesystem;
using namespace srunsh;

// ================================================================
//  Types
// ================================================================
struct PortForward {
    uint16_t    local_port;
    std::string remote_host;
    uint16_t    remote_port;
};

struct SlaveConn {
    int         fd;
    uint32_t    channel;
    RecvBuffer  rbuf;
};

// ================================================================
//  Globals for signal handlers / cleanup
// ================================================================
static volatile sig_atomic_t g_winch = 0;
static struct termios g_orig_termios;
static bool g_raw_mode = false;
static std::string g_ctl_path;            // for cleanup

static void handle_winch(int) { g_winch = 1; }

static void restore_terminal() {
    if (g_raw_mode) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_orig_termios);
        int fl = fcntl(STDIN_FILENO, F_GETFL, 0);
        fcntl(STDIN_FILENO, F_SETFL, fl & ~O_NONBLOCK);
        g_raw_mode = false;
    }
}

static void cleanup_ctl() {
    if (!g_ctl_path.empty()) unlink(g_ctl_path.c_str());
}

static void set_raw_mode() {
    if (!isatty(STDIN_FILENO)) return;
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

// ================================================================
//  Networking helpers
// ================================================================
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
        listen(fd, 16) < 0) { close(fd); return -1; }
    set_nonblock(fd);
    return fd;
}

static int create_unix_listener(const std::string& path) {
    unlink(path.c_str());
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path.c_str());
    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0 ||
        listen(fd, 8) < 0) { close(fd); return -1; }
    chmod(path.c_str(), 0600);
    set_nonblock(fd);
    return fd;
}

static int connect_unix(const std::string& path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path.c_str());
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd); return -1;
    }
    return fd;
}

// ================================================================
//  Deploy server binary
// ================================================================
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
        if (!fs::exists(dst) ||
            fs::last_write_time(src) > fs::last_write_time(dst)) {
            std::error_code ec;
            fs::copy_file(src, dst, fs::copy_options::overwrite_existing, ec);
            if (!ec) chmod(dst.c_str(), 0755);
        }
    } else if (!fs::exists(dst)) {
        fprintf(stderr, "srunsh: server binary not found\n");
        exit(1);
    }
    return dst;
}

// ================================================================
//  Arg parsing helpers
// ================================================================
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
        "  -S jobid              Attach to existing SLURM job\n"
        "  -h, --help            Show this help\n"
        "\n"
        "First invocation with -S becomes the ControlMaster (launches srun).\n"
        "Subsequent invocations reuse the same connection automatically.\n"
        "\n"
        "Example:\n"
        "  srunsh -L 11434:localhost:11434 -S 70029 -- --gres=gpu:4 -- ollama serve\n"
        "  srunsh -S 70029                     # new shell, same GPUs\n"
    );
}

// ================================================================
//  Authentication (master ↔ srunshd)
// ================================================================
static bool do_auth(int wr, int rd, RecvBuffer& rbuf) {
    KeyPair kp;
    if (!load_private_key(srunsh_dir() + "/id_ed25519", kp)) {
        fprintf(stderr, "srunsh: no key found — run srunsh-keygen first\n");
        return false;
    }
    Message msg;
    while (true) {
        ssize_t n = rbuf.feed(rd);
        if (n <= 0) { perror("srunsh: read challenge"); return false; }
        if (rbuf.parse(msg)) break;
    }
    if (msg.type != MSG_AUTH_CHALLENGE || msg.payload.size() != 32) {
        fprintf(stderr, "srunsh: bad handshake\n"); return false;
    }
    std::vector<uint8_t> sig;
    if (!sign_data(kp, msg.payload.data(), msg.payload.size(), sig)) {
        fprintf(stderr, "srunsh: signing failed\n"); return false;
    }
    Packer p; p.raw(kp.pub_key); p.raw(sig);
    if (!send_msg(wr, make_msg(MSG_AUTH_RESPONSE, 0, p.finish())))
        return false;
    while (true) {
        ssize_t n = rbuf.feed(rd);
        if (n <= 0) return false;
        if (rbuf.parse(msg)) break;
    }
    if (msg.type == MSG_AUTH_OK) return true;
    fprintf(stderr, "srunsh: authentication failed\n");
    return false;
}

// ================================================================
//  Slave mode — connect to existing ControlMaster
// ================================================================
static int run_as_slave(int master_fd,
                        const std::string& remote_cmd) {
    // Send SHELL_REQ to master
    {
        struct winsize ws{24, 80, 0, 0};
        if (isatty(STDIN_FILENO))
            ioctl(STDIN_FILENO, TIOCGWINSZ, &ws);
        Packer p;
        p.u16(ws.ws_row); p.u16(ws.ws_col); p.str(remote_cmd);
        if (!send_msg(master_fd, make_msg(MSG_SHELL_REQ, 0, p.finish()))) {
            fprintf(stderr, "srunsh: master not responding\n");
            return 1;
        }
    }

    set_raw_mode();
    set_nonblock(master_fd);
    set_nonblock(STDIN_FILENO);

    struct sigaction sa{};
    sa.sa_handler = handle_winch;
    sigaction(SIGWINCH, &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);

    RecvBuffer rbuf;
    int  exit_code = 0;
    bool running   = true;

    while (running) {
        if (g_winch) {
            g_winch = 0;
            struct winsize ws{};
            ioctl(STDIN_FILENO, TIOCGWINSZ, &ws);
            Packer p; p.u16(ws.ws_row); p.u16(ws.ws_col);
            send_msg(master_fd, make_msg(MSG_SHELL_RESIZE, 0, p.finish()));
        }

        struct pollfd pfds[2] = {
            {master_fd,    POLLIN, 0},
            {STDIN_FILENO, POLLIN, 0},
        };
        if (poll(pfds, 2, 500) < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // From master
        if (pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = rbuf.feed(master_fd);
            if (n == 0)                   { running = false; break; }
            if (n < 0 && errno != EAGAIN) { running = false; break; }
            Message msg;
            while (rbuf.parse(msg)) {
                if (msg.type == MSG_SHELL_DATA)
                    (void)!write(STDOUT_FILENO,
                                 msg.payload.data(), msg.payload.size());
                else if (msg.type == MSG_SHELL_EXIT) {
                    Unpacker u(msg.payload);
                    exit_code = static_cast<int>(u.u32());
                    running = false;
                }
            }
        }

        // From terminal
        if (pfds[1].revents & POLLIN) {
            uint8_t buf[4096];
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n > 0)
                send_msg(master_fd,
                         make_msg(MSG_SHELL_DATA, 0, buf,
                                  static_cast<size_t>(n)));
        }
    }

    restore_terminal();
    close(master_fd);
    return exit_code;
}

// ================================================================
//  Master mode — launch srun, manage multiplexed sessions
// ================================================================
static int run_as_master(const std::string& job_id,
                         const std::vector<std::string>& srun_opts,
                         const std::string& remote_cmd,
                         const std::vector<PortForward>& forwards) {
    // ---- deploy & build srun command ----
    std::string server_bin = deploy_server();

    std::vector<std::string> cmd;
    cmd.emplace_back("srun");
    cmd.emplace_back("--unbuffered");
    if (!job_id.empty())
        cmd.push_back("--jobid=" + job_id);
    for (auto& o : srun_opts) cmd.push_back(o);
    cmd.push_back(server_bin);

    std::vector<char*> cargv;
    for (auto& s : cmd) cargv.push_back(const_cast<char*>(s.c_str()));
    cargv.push_back(nullptr);

    // ---- fork srun ----
    int to_child[2], from_child[2];
    if (pipe(to_child) < 0 || pipe(from_child) < 0) {
        perror("srunsh: pipe"); return 1;
    }
    pid_t srun_pid = fork();
    if (srun_pid < 0) { perror("srunsh: fork"); return 1; }
    if (srun_pid == 0) {
        close(to_child[1]); close(from_child[0]);
        dup2(to_child[0],   STDIN_FILENO);
        dup2(from_child[1], STDOUT_FILENO);
        close(to_child[0]); close(from_child[1]);
        execvp(cargv[0], cargv.data());
        perror("srunsh: exec srun"); _exit(127);
    }
    close(to_child[0]); close(from_child[1]);
    int wr_fd = to_child[1];     // → server
    int rd_fd = from_child[0];   // ← server

    // ---- authenticate ----
    RecvBuffer rbuf;
    if (!do_auth(wr_fd, rd_fd, rbuf)) {
        close(wr_fd); close(rd_fd);
        kill(srun_pid, SIGTERM); waitpid(srun_pid, nullptr, 0);
        return 1;
    }

    // ---- send SHELL_REQ for our own session (channel 0) ----
    {
        struct winsize ws{24, 80, 0, 0};
        if (isatty(STDIN_FILENO))
            ioctl(STDIN_FILENO, TIOCGWINSZ, &ws);
        Packer p;
        p.u16(ws.ws_row); p.u16(ws.ws_col); p.str(remote_cmd);
        send_msg(wr_fd, make_msg(MSG_SHELL_REQ, 0, p.finish()));
    }

    // ---- port-forward listeners ----
    std::map<int, size_t> listener_idx;
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

    // ---- control socket ----
    int ctl_fd = -1;
    if (!job_id.empty()) {
        std::string ctl_dir = srunsh_dir() + "/ctl";
        fs::create_directories(ctl_dir);
        g_ctl_path = ctl_dir + "/" + job_id + ".sock";
        ctl_fd = create_unix_listener(g_ctl_path);
        if (ctl_fd >= 0)
            atexit(cleanup_ctl);
        else
            fprintf(stderr, "srunsh: warning: could not create control socket\n");
    }

    // ---- raw mode & signals ----
    set_raw_mode();
    set_nonblock(rd_fd);
    set_nonblock(STDIN_FILENO);

    { struct sigaction sa{}; sa.sa_handler = handle_winch;
      sigaction(SIGWINCH, &sa, nullptr); }
    signal(SIGPIPE, SIG_IGN);

    // ---- tracking structures ----
    std::map<int, SlaveConn>  slaves;        // slave fd → info
    std::map<uint32_t, int>   chan_slave;     // channel → slave fd
    uint32_t next_shell = 1;                 // 0 is ours

    std::map<uint32_t, int>   fwd_fd;        // fwd channel → tcp socket
    std::map<int, uint32_t>   fd_fwd;        // tcp socket → fwd channel
    uint32_t next_fwd = 0x00800000;          // port-forward channel range

    int  exit_code = 0;
    bool running   = true;
    bool own_alive = true;                   // channel 0

    while (running) {
        // ---- SIGWINCH ----
        if (g_winch) {
            g_winch = 0;
            struct winsize ws{};
            ioctl(STDIN_FILENO, TIOCGWINSZ, &ws);
            Packer p; p.u16(ws.ws_row); p.u16(ws.ws_col);
            send_msg(wr_fd, make_msg(MSG_SHELL_RESIZE, 0, p.finish()));
        }

        // ---- build poll set ----
        std::vector<struct pollfd> pfds;
        pfds.push_back({rd_fd, POLLIN, 0});              // [0] server
        pfds.push_back({STDIN_FILENO, POLLIN, 0});        // [1] terminal
        if (ctl_fd >= 0)
            pfds.push_back({ctl_fd, POLLIN, 0});          // [2] control
        for (auto& [fd, _] : listener_idx)
            pfds.push_back({fd, POLLIN, 0});
        for (auto& [fd, _] : slaves)
            pfds.push_back({fd, POLLIN, 0});
        for (auto& [fd, _] : fd_fwd)
            pfds.push_back({fd, POLLIN, 0});

        if (poll(pfds.data(), pfds.size(), 500) < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (size_t pi = 0; pi < pfds.size(); ++pi) {
            auto& pfd = pfds[pi];
            if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR)))
                continue;

            // ---- [server → dispatch] ----
            if (pfd.fd == rd_fd) {
                ssize_t n = rbuf.feed(rd_fd);
                if (n == 0)                   { running = false; break; }
                if (n < 0 && errno != EAGAIN) { running = false; break; }

                Message msg;
                while (rbuf.parse(msg)) {
                    // Shell data/exit: route to terminal or slave
                    if (msg.type == MSG_SHELL_DATA ||
                        msg.type == MSG_SHELL_EXIT) {
                        if (msg.channel == 0) {
                            // Our own session
                            if (msg.type == MSG_SHELL_DATA)
                                (void)!write(STDOUT_FILENO,
                                             msg.payload.data(),
                                             msg.payload.size());
                            else {
                                Unpacker u(msg.payload);
                                exit_code = static_cast<int>(u.u32());
                                own_alive = false;
                                if (slaves.empty()) running = false;
                            }
                        } else if (chan_slave.count(msg.channel)) {
                            int sfd = chan_slave[msg.channel];
                            uint32_t orig_ch = msg.channel;
                            // Remap channel back to 0 for slave
                            msg.channel = 0;
                            send_msg(sfd, msg);
                            if (msg.type == MSG_SHELL_EXIT) {
                                close(sfd);
                                slaves.erase(sfd);
                                chan_slave.erase(orig_ch);
                            }
                        }
                    }
                    // Port forward responses
                    else if (msg.type == MSG_FWD_ACCEPT) {
                        // nothing to do
                    }
                    else if (msg.type == MSG_FWD_REJECT ||
                             msg.type == MSG_FWD_CLOSE) {
                        if (fwd_fd.count(msg.channel)) {
                            int cfd = fwd_fd[msg.channel];
                            close(cfd);
                            fd_fwd.erase(cfd);
                            fwd_fd.erase(msg.channel);
                        }
                    }
                    else if (msg.type == MSG_FWD_DATA) {
                        if (fwd_fd.count(msg.channel))
                            (void)!write(fwd_fd[msg.channel],
                                         msg.payload.data(),
                                         msg.payload.size());
                    }
                    if (!running) break;
                }
            }

            // ---- [terminal → channel 0] ----
            else if (pfd.fd == STDIN_FILENO) {
                uint8_t buf[4096];
                ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
                if (n > 0 && own_alive)
                    send_msg(wr_fd,
                             make_msg(MSG_SHELL_DATA, 0, buf,
                                      static_cast<size_t>(n)));
            }

            // ---- [control socket → accept slave] ----
            else if (pfd.fd == ctl_fd) {
                int sfd = accept(ctl_fd, nullptr, nullptr);
                if (sfd < 0) continue;

                // Read SHELL_REQ from slave (small msg, local socket)
                RecvBuffer srb;
                Message sm;
                bool got = false;
                for (int tries = 0; tries < 50; ++tries) {
                    ssize_t n = srb.feed(sfd);
                    if (n <= 0) break;
                    if (srb.parse(sm)) { got = true; break; }
                }
                if (!got || sm.type != MSG_SHELL_REQ) {
                    close(sfd); continue;
                }

                uint32_t ch = next_shell++;
                sm.channel = ch;
                send_msg(wr_fd, sm);              // forward to server

                set_nonblock(sfd);
                slaves[sfd] = {sfd, ch, std::move(srb)};
                chan_slave[ch] = sfd;
            }

            // ---- [port-forward listener → accept] ----
            else if (listener_idx.count(pfd.fd)) {
                int conn = accept(pfd.fd, nullptr, nullptr);
                if (conn < 0) continue;
                set_nonblock(conn);
                uint32_t ch  = next_fwd++;
                size_t   idx = listener_idx[pfd.fd];
                Packer p;
                p.str(forwards[idx].remote_host);
                p.u16(forwards[idx].remote_port);
                send_msg(wr_fd, make_msg(MSG_FWD_OPEN, ch, p.finish()));
                fwd_fd[ch]   = conn;
                fd_fwd[conn] = ch;
            }

            // ---- [slave socket → server] ----
            else if (slaves.count(pfd.fd)) {
                auto& sl = slaves[pfd.fd];
                ssize_t n = sl.rbuf.feed(pfd.fd);
                if (n <= 0 && errno != EAGAIN) {
                    // Slave disconnected — close its server session
                    send_msg(wr_fd, make_msg(MSG_SHELL_CLOSE, sl.channel));
                    chan_slave.erase(sl.channel);
                    close(pfd.fd);
                    slaves.erase(pfd.fd);
                    if (!own_alive && slaves.empty()) running = false;
                    continue;
                }
                Message sm;
                while (sl.rbuf.parse(sm)) {
                    // Remap slave channel 0 → actual channel
                    sm.channel = sl.channel;
                    send_msg(wr_fd, sm);
                }
            }

            // ---- [port-forward socket → server] ----
            else if (fd_fwd.count(pfd.fd)) {
                uint32_t ch = fd_fwd[pfd.fd];
                uint8_t buf[8192];
                ssize_t n = read(pfd.fd, buf, sizeof(buf));
                if (n > 0) {
                    send_msg(wr_fd,
                             make_msg(MSG_FWD_DATA, ch, buf,
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
    restore_terminal();
    close(wr_fd); close(rd_fd);
    for (auto& [fd, _] : listener_idx) close(fd);
    for (auto& [fd, _] : slaves)       close(fd);
    for (auto& [_, fd]  : fwd_fd)      close(fd);
    if (ctl_fd >= 0) close(ctl_fd);

    int wst;
    if (waitpid(srun_pid, &wst, WNOHANG) == 0) {
        kill(srun_pid, SIGTERM);
        waitpid(srun_pid, &wst, 0);
    }
    return exit_code;
}

// ================================================================
//  main
// ================================================================
int main(int argc, char* argv[]) {
    std::vector<PortForward> forwards;
    std::string              job_id;

    // 1. Parse srunsh options
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

    // 2. srun options
    std::vector<std::string> srun_opts;
    while (i < argc) {
        std::string a = argv[i];
        if (a == "--") { ++i; break; }
        srun_opts.push_back(a);
        ++i;
    }

    // 3. Remote command
    std::string remote_cmd;
    for (; i < argc; ++i) {
        if (!remote_cmd.empty()) remote_cmd += ' ';
        remote_cmd += argv[i];
    }

    // ---- decide: slave or master ----
    if (!job_id.empty()) {
        std::string ctl_dir  = srunsh_dir() + "/ctl";
        fs::create_directories(ctl_dir);
        std::string ctl_path = ctl_dir + "/" + job_id + ".sock";

        int master_fd = connect_unix(ctl_path);
        if (master_fd >= 0) {
            // Existing master — become slave.
            // srun_opts are irrelevant for slaves; treat as command
            // so that `srunsh -S X -- fish` works (not just `-- -- fish`).
            if (remote_cmd.empty() && !srun_opts.empty()) {
                for (auto& o : srun_opts) {
                    if (!remote_cmd.empty()) remote_cmd += ' ';
                    remote_cmd += o;
                }
            }
            return run_as_slave(master_fd, remote_cmd);
        }
        // No master yet — fall through to become master
    }

    return run_as_master(job_id, srun_opts, remote_cmd, forwards);
}
