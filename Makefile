build:
	docker build -t dropit:latest .

run:
	docker run -p 8080:80 -it --rm --privileged=true --name dropit dropit:latest
