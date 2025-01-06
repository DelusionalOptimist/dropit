FROM golang:1.20 as build

RUN apt update -y; apt install -y build-essential clang libbpf-dev bpftool linux-headers-generic gcc-multilib
RUN  ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
WORKDIR /build
ADD . .
RUN make build

# the final image
FROM debian:stable

#RUN apt update -y; apt install -y apache2
RUN apt update -y; apt install -y inotify-tools
WORKDIR /dropit
COPY scripts/entrypoint.sh /dropit/entrypoint.sh
COPY --from=build /build/bpf/vmlinux.h /dropit/vmlinux.h
COPY --from=build /build/bpf/daemon.o /dropit/daemon.o
COPY --from=build /build/dropit /dropit/dropit

COPY --from=delusionaloptimist/goserver /goserver /goserver

ENTRYPOINT ["/dropit/entrypoint.sh"]
