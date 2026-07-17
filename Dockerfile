ARG AWS_CLI_VERSION=2.22.35

FROM golang:1.22-bullseye AS go-build

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

ENV GOPROXY=https://proxy.golang.org,direct
ENV GOSUMDB=sum.golang.org
ENV CGO_ENABLED=1

RUN echo "Installing gau..." && \
    timeout 600 go install -v github.com/lc/gau/v2/cmd/gau@v2.2.3

RUN echo "Installing naabu..." && \
    timeout 600 go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.0

RUN echo "Installing nuclei..." && \
    timeout 600 go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.2.9

RUN echo "Installing httpx..." && \
    timeout 600 go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.6.6

RUN echo "Installing ffuf..." && \
    timeout 600 go install -v github.com/ffuf/ffuf/v2@v2.1.0

RUN echo "Installing tlsx..." && \
    timeout 600 go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@v1.1.6

RUN echo "Installing subfinder..." && \
    timeout 600 go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.6

RUN echo "Verifying Go tools..." && \
    ls -la /go/bin/ && \
    /go/bin/nuclei -version && \
    echo "Go tools installation completed successfully"

# AWS CLI v2 via Docker Hub (same bits as ECR public). Some CI/runner networks block or time out to public.ecr.aws.
FROM amazon/aws-cli:${AWS_CLI_VERSION} AS awscli

FROM python:3.11-slim AS final

LABEL org.opencontainers.image.description="Appollo (AWS CLI from Debian; avoids blocked AWS/ECR download hosts during image build)"

ENV PYTHONUNBUFFERED=1
ENV PATH="/usr/local/go/bin:/go/bin:${PATH}"
ENV GOPATH="/go"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        make automake gcc g++ wget git libpcap-dev nmap libssl-dev \
        curl gpg ca-certificates build-essential zlib1g-dev libffi-dev awscli && \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    apt-get update -y && \
    apt-get install -y --no-install-recommends google-cloud-sdk && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN python --version && pip --version

COPY --from=go-build /usr/local/go /usr/local/go
COPY --from=go-build /go/bin /go/bin

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . /app
RUN mkdir -p /etc/config && \
    useradd -r -u 1001 -s /bin/false appollo && \
    chown -R appollo /app /etc/config

USER appollo

# CronJob AWS scans invoke `aws`; fail the image build if the binary is broken.
RUN python3 --version && go version && nuclei --version && \
    aws --version && command -v aws

ENTRYPOINT ["python3", "src/appollo.py"]
