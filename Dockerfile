# Multi-stage build for faster builds
FROM ubuntu:20.04 AS base

ENV DEBIAN_FRONTEND=noninteractive

# Install all system dependencies in one layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        make automake gcc g++ subversion wget git libc-dev libpcap-dev nmap curl ca-certificates \
        build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev \
        libreadline-dev libffi-dev libsqlite3-dev libbz2-dev gpg && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Python build stage
FROM base AS python-build

# Download and compile Python 3.9.6
RUN wget -q https://www.python.org/ftp/python/3.9.6/Python-3.9.6.tgz && \
    tar -xf Python-3.9.6.tgz && \
    cd Python-3.9.6 && \
    ./configure --enable-optimizations --prefix=/usr/local && \
    make -j $(nproc) && \
    make altinstall && \
    cd .. && \
    rm -rf Python-3.9.6 Python-3.9.6.tgz

# Go build stage
FROM base AS go-build

# Install Go
RUN wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz && \
    rm go1.21.5.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="$GOPATH/bin:/usr/local/go/bin:$PATH"

# Install Go tools in parallel
RUN go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.3 && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.1.7 && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest

# Final stage
FROM base AS final

# Copy Python from build stage
COPY --from=python-build /usr/local/bin/python3.9 /usr/local/bin/python3.9
COPY --from=python-build /usr/local/bin/pip3.9 /usr/local/bin/pip3.9
COPY --from=python-build /usr/local/lib/python3.9 /usr/local/lib/python3.9
COPY --from=python-build /usr/local/include/python3.9 /usr/local/include/python3.9

# Create symlinks for python3 and pip3
RUN ln -sf /usr/local/bin/python3.9 /usr/local/bin/python3 && \
    ln -sf /usr/local/bin/pip3.9 /usr/local/bin/pip3 && \
    ln -sf /usr/local/bin/pip3.9 /usr/local/bin/pip

# Copy Go tools from build stage
COPY --from=go-build /usr/local/go /usr/local/go
COPY --from=go-build /go/bin /go/bin

ENV PATH="/usr/local/go/bin:/go/bin:${PATH}"

# Install Google Cloud SDK
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    apt-get update -y && \
    apt-get install -y --no-install-recommends google-cloud-sdk && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create app directory and set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip==24.2 && \
    pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . /app

# Create necessary directories
RUN mkdir -p /etc/config

# Verify installations
RUN python3 --version && \
    pip3 --version && \
    go version && \
    nuclei --version && \
    ffuf -V && \
    gcloud --version

ENTRYPOINT ["python3", "src/appollo.py"]