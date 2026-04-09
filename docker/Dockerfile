FROM python:3.11-slim

# System dependencies for tkinter + customtkinter
RUN apt-get update && apt-get install -y \
    python3-tk \
    tk-dev \
    xvfb \
    x11-utils \
    libx11-6 \
    libxext6 \
    libxrender1 \
    nmap \
    git \
    curl \
    tor \
    && rm -rf /var/lib/apt/lists/*

# Go tools
RUN curl -Lo /tmp/go.tar.gz https://go.dev/dl/go1.22.0.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /app
COPY . .

RUN mkdir -p /app/db /app/logs /app/reports /app/screenshots /app/wordlists

EXPOSE 8877 5353

CMD ["python3", "main.py"]
