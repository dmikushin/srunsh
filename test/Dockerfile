FROM debian:bullseye-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake libssl-dev \
    slurm-wlm slurm-client munge \
    python3 netcat-openbsd procps \
    && rm -rf /var/lib/apt/lists/*

# Generate a shared munge key (baked into image — same for all containers)
RUN dd if=/dev/urandom of=/etc/munge/munge.key bs=1024 count=1 2>/dev/null \
    && chown munge:munge /etc/munge/munge.key \
    && chmod 400 /etc/munge/munge.key

# Build srunsh
COPY CMakeLists.txt /src/CMakeLists.txt
COPY src/ /src/src/

WORKDIR /src/build
RUN cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc) && make install

WORKDIR /
