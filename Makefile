BINARY := sshtunnel-panel
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build run dev clean fmt cross

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

# Run locally without touching /etc (uses ./dev-config and ./dev-data).
dev:
	mkdir -p dev-config dev-data
	SSHTP_CONFIG_DIR=$(PWD)/dev-config SSHTP_DATA_DIR=$(PWD)/dev-data \
		go run . serve

fmt:
	go fmt ./...
	go vet ./...

cross:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 .

clean:
	rm -rf $(BINARY) dist dev-config dev-data
