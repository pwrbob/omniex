# Development image for running the complete local CI suite.
#
# Build with:
#   scripts/dev-container.sh build
#
# Open a shell with:
#   scripts/dev-container.sh
#
# Run CI with:
#   scripts/dev-container.sh bash -lc 'scripts/ci.sh'

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV CARGO_HOME=/opt/cargo
ENV RUSTUP_HOME=/opt/rustup
ENV PATH=/opt/cargo/bin:${PATH}

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bzip2 \
        build-essential \
        ca-certificates \
        curl \
        file \
        git \
        libargon2-dev \
        libbz2-dev \
        libgmp-dev \
        libkrb5-dev \
        liblzma-dev \
        libnss3-dev \
        libpcap-dev \
        libpcre2-dev \
        libsodium-dev \
        libssl-dev \
        libzstd-dev \
        openssl \
        p7zip-full \
        pkg-config \
        python3 \
        python3-asn1crypto \
        python3-bsddb3 \
        python3-cbor2 \
        python3-lxml \
        python3-olefile \
        python3-pip \
        python3-protobuf \
        python3-pyasn1 \
        python3-pycryptodome \
        python3-scapy \
        libcompress-raw-lzma-perl \
        tshark \
        unzip \
        xxd \
        xz-utils \
        zip \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir --break-system-packages pysap pycryptodome

WORKDIR /opt/omniex
COPY scripts/build-hashcat.sh scripts/build-john.sh scripts/
RUN chmod +x scripts/build-hashcat.sh scripts/build-john.sh \
    && OMNIEX_REFERENCE_DIR=/opt/reference scripts/build-hashcat.sh \
    && OMNIEX_REFERENCE_DIR=/opt/reference scripts/build-john.sh \
    && chmod -R a+rX /opt/reference \
    && chmod -R a+rwX /opt/reference/john-*/run

RUN chmod -R a+rwX /opt/reference/hashcat-8.0.0

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh \
    && sh /tmp/rustup-init.sh -y --no-modify-path --profile minimal --default-toolchain 1.100.0 \
    && rustup component add rustfmt clippy \
    && rustup toolchain install 1.90.0 --profile minimal \
    && rm /tmp/rustup-init.sh \
    && chmod -R a+rwX "$RUSTUP_HOME" "$CARGO_HOME"

ENV OMNIEX_HASHCAT=/opt/reference/hashcat-8.0.0/hashcat
ENV OMNIEX_JOHN=/opt/reference/john-5184bc0b8c105f8c5978b112e723d65b2de3e63e/run/john
ENV OMNIEX_JOHN_RUN=/opt/reference/john-5184bc0b8c105f8c5978b112e723d65b2de3e63e/run
ENV LD_LIBRARY_PATH=/opt/reference/hashcat-8.0.0

RUN git config --system --add safe.directory '*'

WORKDIR /work
CMD ["bash"]
