FROM golang:1.20 as build

WORKDIR /build

RUN apt update -y; apt install -y build-essential clang libbpf-dev

ADD . .

RUN make build

FROM debian:stable

RUN apt -y update; apt -y install apache2
WORKDIR /app

COPY entrypoint.sh /app/entrypoint.sh
COPY vmlinux.h /app/vmlinux.h
COPY --from=build /build/daemon.o /app/daemon.o
COPY --from=build /build/dropit /app/dropit

CMD ["bash", "/app/entrypoint.sh"]
