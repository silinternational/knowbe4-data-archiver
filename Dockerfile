FROM golang:1.17

# Install packages
RUN curl -fsSL https://deb.nodesource.com/setup_16.x | bash -
RUN apt-get install -y nodejs

RUN alias ll="ls -al"

# Copy in source and install deps
RUN mkdir -p /app
WORKDIR /app

RUN npm --no-fund install -g serverless@3

COPY ./ .

RUN go get ./...
