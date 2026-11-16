BIN := bin/honeypot

.PHONY: build run test lint fmt vet tidy clean fidelity

build:
	go build -o $(BIN) ./cmd/honeypot

run: build
	./$(BIN)

test:
	go test -race ./...

lint: fmt vet

fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...

tidy:
	go mod tidy

# Compare the honeypot with a real Ubuntu 22.04 container (needs Docker).
fidelity:
	scripts/fidelity.sh

clean:
	rm -rf bin
