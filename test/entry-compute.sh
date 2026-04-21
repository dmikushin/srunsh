#!/bin/bash
set -e

# Fix munge runtime dirs
mkdir -p /run/munge /var/log/munge
chown munge:munge /run/munge /var/log/munge /etc/munge/munge.key
chmod 700 /run/munge
chmod 400 /etc/munge/munge.key

# Start munge (--force skips fs permission checks in container)
munged --force
sleep 0.5

# Create spool directory
mkdir -p /var/spool/slurmd

# Wait for controller to be reachable
echo "Waiting for slurmctld..."
for i in $(seq 1 60); do
    if sinfo 2>/dev/null | grep -q test; then
        break
    fi
    sleep 1
done

# Wait for authorized_keys (deposited by login node via shared volume)
echo "Waiting for authorized_keys..."
for i in $(seq 1 60); do
    if [ -f /root/.srunsh/authorized_keys ]; then
        echo "Got authorized_keys."
        break
    fi
    sleep 0.5
done

# Start slurmd in foreground
exec slurmd -D
