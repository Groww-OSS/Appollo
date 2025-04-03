FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y make automake gcc g++ subversion wget git libc-dev libpcap-dev nmap curl

RUN apt update

RUN apt install -y python3.9 python3.9-dev

RUN apt purge -y python3.8 python3.8-dev

RUN apt install -y python3-pip

RUN ls /usr/bin/

RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 1

RUN update-alternatives --install /usr/bin/pip3 pip3 / 1

RUN python3 --version && sleep 5

RUN mkdir /app

WORKDIR /app

COPY --from=golang /usr/local/go/ /usr/local/go/
 
ENV PATH="/usr/local/go/bin:${PATH}"

COPY . /app

ENV GOPATH /go

ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN go install -v github.com/lc/gau/v2/cmd/gau@latest

RUN gau --version
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.3
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/ffuf/ffuf/v2@latest
RUN go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest

RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && apt-get update -y && apt-get install google-cloud-sdk -y

RUN gcloud --version

COPY requirements.txt .
RUN pip install --upgrade pip==24.2
RUN pip install -r  requirements.txt

ENTRYPOINT ["python3", "src/appollo.py"]