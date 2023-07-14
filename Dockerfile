FROM golang:1.20 as build

RUN apt update -y; apt install -y build-essential clang libbpf-dev

WORKDIR /build
ADD . .
RUN make build

# the final image
FROM debian:stable

#RUN apt update -y; apt install -y apache2

WORKDIR /dropit
COPY scripts/entrypoint.sh /dropit/entrypoint.sh
COPY vmlinux.h /dropit/vmlinux.h
COPY --from=build /build/daemon.o /dropit/daemon.o
COPY --from=build /build/dropit /dropit/dropit

COPY --from=delusionaloptimist/goserver /goserver /goserver

ENTRYPOINT ["/dropit/entrypoint.sh"]
