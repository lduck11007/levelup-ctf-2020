FROM ubuntu:18.04
RUN dpkg --add-architecture i386
RUN apt-get update && apt-get install -y libc6:i386 build-essential socat gcc-multilib

RUN useradd -ms /bin/bash user
COPY . /bankofmonsec
WORKDIR /bankofmonsec

RUN make
RUN chmod +x bankofmonsec

EXPOSE 9000
USER user

CMD socat tcp-l:9000,reuseaddr,fork exec:./bankofmonsec,pty,echo=0,raw,iexten=0