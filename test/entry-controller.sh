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
mkdir -p /var/spool/slurmctld

# Start slurmctld in foreground
exec slurmctld -D
