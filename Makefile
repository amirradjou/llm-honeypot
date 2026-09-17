BIN := bin/honeypot

.PHONY: build run test lint fmt vet tidy clean

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

clean:
	rm -rf bin
