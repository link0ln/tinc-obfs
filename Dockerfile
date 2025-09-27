FROM ubuntu:22.04

# Install build dependencies and runtime utilities
RUN apt-get update && apt-get install -y \
    build-essential \
    autoconf \
    automake \
    pkg-config \
    libssl-dev \
    zlib1g-dev \
    liblzo2-dev \
    libncurses5-dev \
    libreadline-dev \
    texinfo \
    iproute2 \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /usr/src/tinc

# Copy tinc source code
COPY . .

# Configure, build and install tinc
RUN ./configure --prefix=/usr/local && \
    make && \
    make install

# Create runtime user
RUN useradd -r -s /bin/false tinc

# Expose typical tinc port
EXPOSE 655/tcp 655/udp

# Default command
CMD ["/usr/local/sbin/tincd", "-D"]