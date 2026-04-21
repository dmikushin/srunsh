#!/bin/bash
# Integration test: srunsh over a real SLURM cluster

set -e

# Fix munge runtime dirs
mkdir -p /run/munge /var/log/munge
chown munge:munge /run/munge /var/log/munge /etc/munge/munge.key
chmod 700 /run/munge
chmod 400 /etc/munge/munge.key

# Start munge (--force skips fs permission checks in container)
munged --force
sleep 0.5

# Generate srunsh keypair (writes to shared volume /root/.srunsh)
srunsh-keygen

# Wait for SLURM to be fully operational (both nodes idle)
echo "Waiting for SLURM cluster..."
for i in $(seq 1 60); do
    IDLE_COUNT=$(sinfo -h -t idle -o "%D" 2>/dev/null | awk '{s+=$1}END{print s+0}')
    if [ "$IDLE_COUNT" -ge 2 ]; then
        break
    fi
    sleep 1
done
if [ "$(sinfo -h -t idle -o '%D' 2>/dev/null | awk '{s+=$1}END{print s+0}')" -lt 2 ]; then
    echo "FAIL: SLURM cluster not ready (need 2 idle nodes)"
    sinfo 2>&1 || true
    exit 1
fi
echo "SLURM cluster ready:"
sinfo

# --- Tests (no set -e, we check results manually) ---
set +e

PASS=0
FAIL=0

echo ""
echo "=== Test 1: run remote command ==="
OUT=$(echo "" | timeout 30 srunsh -- -- "echo hello_srunsh; exit 0" 2>/dev/null)
if echo "$OUT" | grep -q "hello_srunsh"; then
    echo "PASS"
    PASS=$((PASS+1))
else
    echo "FAIL: got '$OUT'"
    FAIL=$((FAIL+1))
fi

echo "=== Test 2: exit code propagation ==="
timeout 30 srunsh -- -- "exit 42" </dev/null 2>/dev/null
RC=$?
if [ "$RC" -eq 42 ]; then
    echo "PASS"
    PASS=$((PASS+1))
else
    echo "FAIL: expected 42, got $RC"
    FAIL=$((FAIL+1))
fi

echo "=== Test 3: port forwarding ==="
# Run echo server on the login node
python3 -c "
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 19876)); s.listen(1); s.settimeout(20)
c,_ = s.accept(); c.sendall(c.recv(1024)); c.close(); s.close()
" &
ECHO_PID=$!
sleep 1

# Port forward: local 19877 → login:19876 (compute connects back to login)
timeout 30 srunsh -L 19877:login:19876 -- -- "sleep 15" </dev/null 2>/dev/null &
SRUNSH_PID=$!
sleep 4

REPLY=$(python3 -c "
import socket, time
s = socket.socket(); s.settimeout(5)
s.connect(('127.0.0.1', 19877))
s.sendall(b'ping_fwd')
time.sleep(0.5)
print(s.recv(1024).decode(), end='')
s.close()
" 2>/dev/null)
kill $SRUNSH_PID 2>/dev/null
wait $SRUNSH_PID 2>/dev/null
kill $ECHO_PID 2>/dev/null
wait $ECHO_PID 2>/dev/null

if [ "$REPLY" = "ping_fwd" ]; then
    echo "PASS"
    PASS=$((PASS+1))
else
    echo "FAIL: got '$REPLY'"
    FAIL=$((FAIL+1))
fi

echo "=== Test 4: multi-node (per-node ControlMaster) ==="
# Allocate a 2-node job in the background (salloc --no-shell holds the allocation)
salloc -N2 --no-shell -J srunsh-test &>/dev/null &
SALLOC_PID=$!
sleep 2

JOBID=$(squeue -h -n srunsh-test -o "%i" | head -1)
if [ -z "$JOBID" ]; then
    echo "FAIL: could not allocate 2-node job"
    kill $SALLOC_PID 2>/dev/null
    FAIL=$((FAIL+1))
else
    echo "  Allocated job $JOBID"

    # Run command on compute1
    OUT1=$(echo "" | timeout 30 srunsh -S "$JOBID" -n compute1 -- -- "hostname; exit 0" 2>/dev/null)
    # Run command on compute2
    OUT2=$(echo "" | timeout 30 srunsh -S "$JOBID" -n compute2 -- -- "hostname; exit 0" 2>/dev/null)

    # Verify each ran on the correct node
    GOT1=$(echo "$OUT1" | grep -o "compute1" | head -1)
    GOT2=$(echo "$OUT2" | grep -o "compute2" | head -1)

    if [ "$GOT1" = "compute1" ] && [ "$GOT2" = "compute2" ]; then
        echo "PASS"
        PASS=$((PASS+1))
    else
        echo "FAIL: expected compute1/compute2, got '$OUT1' / '$OUT2'"
        FAIL=$((FAIL+1))
    fi

    scancel "$JOBID" 2>/dev/null
    kill $SALLOC_PID 2>/dev/null
    wait $SALLOC_PID 2>/dev/null
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
