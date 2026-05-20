APP := macaudit
DIST := dist
GOCACHE ?= $(CURDIR)/.gocache

.PHONY: build run install build-all clean

build:
	GOCACHE=$(GOCACHE) go build -o bin/$(APP) .

run:
	GOCACHE=$(GOCACHE) go run .

install:
	GOCACHE=$(GOCACHE) go install .

build-all:
	mkdir -p $(DIST)
	GOCACHE=$(GOCACHE) GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o $(DIST)/$(APP)-darwin-amd64 .
	GOCACHE=$(GOCACHE) GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o $(DIST)/$(APP)-darwin-arm64 .
	lipo -create -output $(DIST)/$(APP)-darwin-universal $(DIST)/$(APP)-darwin-amd64 $(DIST)/$(APP)-darwin-arm64

clean:
	rm -rf bin $(DIST)
