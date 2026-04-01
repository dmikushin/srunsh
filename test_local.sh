#!/bin/bash
# Integration test: connect client↔server directly using a fake srun
# that just exec's the server binary (last argument).
BUILD="$(cd "$(dirname "$0")/build" && pwd)"
FAKE_DIR=$(mktemp -d)

cat > "$FAKE_DIR/srun" <<'EOF'
#!/bin/bash
exec "${@: -1}"
EOF
chmod +x "$FAKE_DIR/srun"

cleanup() { rm -rf "$FAKE_DIR"; }
trap cleanup EXIT

export PATH="$FAKE_DIR:$PATH"

echo "=== Test 1: run remote command ==="
OUT=$(echo "" | timeout 5 "$BUILD/srunsh" -- -- "echo hello_srunsh; exit 0" 2>/dev/null) || true
if echo "$OUT" | grep -q "hello_srunsh"; then
    echo "PASS"
else
    echo "FAIL: got '$OUT'"
fi

echo "=== Test 2: exit code propagation ==="
timeout 5 "$BUILD/srunsh" -- -- "exit 42" </dev/null 2>/dev/null || RC=$?
RC=${RC:-0}
if [ "$RC" -eq 42 ]; then
    echo "PASS"
else
    echo "FAIL: expected 42, got $RC"
fi

echo "=== Test 3: port forwarding ==="
# Start a TCP echo server on port 19876
python3 -c "
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 19876)); s.listen(1); s.settimeout(5)
c,_ = s.accept(); c.sendall(c.recv(1024)); c.close(); s.close()
" &
ECHO_PID=$!
sleep 0.3

# srunsh with port forward — connect local:19877 → localhost:19876
timeout 10 "$BUILD/srunsh" -L 19877:127.0.0.1:19876 -- -- "sleep 5" </dev/null 2>/dev/null &
SRUNSH_PID=$!
sleep 1.5

REPLY=$(python3 -c "
import socket, time
s = socket.socket(); s.settimeout(3)
s.connect(('127.0.0.1', 19877))
s.sendall(b'ping_fwd')
time.sleep(0.5)
print(s.recv(1024).decode(), end='')
s.close()
" 2>/dev/null || true)
kill $SRUNSH_PID 2>/dev/null; wait $SRUNSH_PID 2>/dev/null || true
kill $ECHO_PID 2>/dev/null;   wait $ECHO_PID   2>/dev/null || true

if [ "$REPLY" = "ping_fwd" ]; then
    echo "PASS"
else
    echo "FAIL: got '$REPLY'"
fi
