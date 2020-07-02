# Get Baseline Dockerfile
FROM ubuntu:19.04
RUN dpkg --add-architecture i386
RUN apt-get update && apt-get install -y libc6:i386 build-essential socat gcc-multilib

# Setup Workspace
RUN useradd -ms /bin/bash user
COPY ./challenge /challenge
WORKDIR /challenge

# Compile Challenge
RUN make
RUN chmod +x challenge

# Setup Challenge Environment 
EXPOSE 1337
USER user

# Connects challenge to a port, allowing challengers to access it on repeat connections.
CMD socat tcp-l:1337,reuseaddr,fork exec:./challenge,pty,echo=0,raw,iexten=0
