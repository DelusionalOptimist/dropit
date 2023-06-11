FROM golang:1.20 as build
WORKDIR /build
ADD . .
RUN go build -o dropit .

FROM archlinux:latest
RUN pacman -Syu --noconfirm apache
WORKDIR /app
COPY entrypoint.sh /app/entrypoint.sh
COPY --from=build /build/dropit /app/dropit
CMD ["bash", "/app/entrypoint.sh"]
