# ── Stage 1: Build C++ capturer ───────────────────────────────────────────
FROM ubuntu:22.04 AS cpp-builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libpcap-dev \
    libboost-all-dev \
    libcurl4-openssl-dev \
    nlohmann-json3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY traffic_capturer_updated/ .
RUN cmake -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build --parallel $(nproc)

# ── Stage 2: Runtime ───────────────────────────────────────────────────────
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libboost-system1.74.0 \
    python3.11 \
    python3-pip \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --upgrade pip

WORKDIR /app

COPY ml_requirements.txt /tmp/ml_requirements.txt
COPY bc_requirements.txt /tmp/bc_requirements.txt
RUN pip3 install \
    -r /tmp/ml_requirements.txt \
    -r /tmp/bc_requirements.txt

COPY updated_model/      /app/updated_model/
COPY updated_blockchain/ /app/updated_blockchain/
COPY target_server.py    /app/target_server.py

COPY --from=cpp-builder /build/build/ids \
                        /app/traffic_capturer_updated/build/ids

COPY supervisord.conf /etc/supervisor/conf.d/ids.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/ids.conf"]
