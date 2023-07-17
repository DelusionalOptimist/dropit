CUR_DIR := $(shell pwd)
BPF_DIR := $(realpath $(CUR_DIR)/bpf)

# run a container with private bridge network and bind to its interface
docker-run: docker-clean
	docker compose up --build --remove-orphans

# run a container with host networking mode and bind to host's interface
docker-run-host: docker-clean docker-build
	docker run -it --rm -v "$(PWD)"/sample:/dropit/sample/:ro --privileged=true --network=host --name=dropit delusionaloptimist/dropit:latest --interface=wlan0 --config=/dropit/sample/dropit.yaml

docker-build:
	docker build -t delusionaloptimist/dropit:latest .

docker-clean:
	docker compose rm -f

docker-push:
	docker push delusionaloptimist/dropit:latest

deploy:
	docker compose up --no-build

deploy-host:
	docker run -it --rm -v /opt/dropit:/opt/dropit:ro --privileged=true --network=host --name=dropit delusionaloptimist/dropit:latest

build: generate
	# paths set according to debian
	CC=clang CGO_CFLAGS="-I /usr/include/bpf" CGO_LDFLAGS="-lelf -lz /usr/lib/x86_64-linux-gnu/libbpf.a" go build -o dropit -ldflags="-w -extldflags "-static"" $(CUR_DIR)/cmd/

generate:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_DIR)/vmlinux.h
	clang -g -O2 -c -target bpf -o $(BPF_DIR)/daemon.o $(BPF_DIR)/daemon.c
