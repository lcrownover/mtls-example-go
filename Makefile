.PHONY: build install clean run container handler
all: build

build:
	@go build -o bin/mtls cmd/mtls/main.go

run: build
	@go run cmd/mtls/main.go

install: build
	@cp bin/mtls /usr/local/bin/mtls

container:
	@docker build -t mtls .

handler:
	@go build -o handler cmd/mtls/main.go

clean:
	@rm -f bin/mtls /usr/local/bin/mtls
