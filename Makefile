LDFLAGS := -s -w

.PHONY: build test integration clean

# Static, stripped binary.
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/bw ./cmd/bw

test:
	go vet ./...
	go test ./...

# Needs podman or docker; starts a throwaway Vaultwarden container.
integration:
	go test -tags integration -count=1 ./integration/

clean:
	rm -rf bin
