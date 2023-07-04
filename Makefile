docker-build:
	docker build -t dropit:latest .

docker-run: docker-build
	docker run -p 8080:80 -it --rm --privileged=true --name dropit dropit:latest

.PHONY: build
build: generate
	# paths set according to debian
	CC=clang CGO_CFLAGS="-I /usr/include/bpf" CGO_LDFLAGS="-lelf -lz /usr/lib/x86_64-linux-gnu/libbpf.a" go build -o dropit -ldflags="-w -extldflags "-static""

generate:
	clang -g -O2 -c -target bpf -o daemon.o daemon.c
