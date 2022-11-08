.PHONY: all
all: checks unit-tests unit-tests-race

.PHONY: checks
checks: check-deps
	@test -z $(shell gofmt -l -s $(shell go list -f '{{.Dir}}' ./... | grep -v mpc) | tee /dev/stderr) || (echo "Fix formatting issues"; exit 1)
	@go vet -all $(shell go list -f '{{.Dir}}' ./... | grep -v mpc)
	find . -name '*.go' | xargs addlicense -check || (echo "Missing license headers"; exit 1)

.PHONY: unit-tests
unit-tests:
	@go test -timeout 480s -cover $(shell go list ./...)

.PHONY: unit-tests-race
unit-tests-race:
	@export GORACE=history_size=7; go test -timeout 960s -race -cover $(shell go list ./...)

.PHONY: check-deps
check-deps:
	@go get -u github.com/google/addlicense

.PHONY: idemixgen
idemixgen:
	@go install ./tools/idemixgen

.PHONY: binaries
binaries: 
	mkdir -p bin/amd64
	GOOS=linux GOARCH=amd64 go build -o bin/amd64/idemixgen tools/idemixgen/main.go

	mkdir -p bin/arm64
	GOOS=darwin GOARCH=arm64 go build -o bin/arm64/idemixgen tools/idemixgen/main.go

.PHONY: deps
deps: $(BUF) $(PROTOC_GEN_GO)

PROJECT := idemix

# This controls the version of buf to install and use.
BUF_VERSION := 1.1.1
PROTOC_VERSION := 3.19.4
PROTOC_GEN_GO_VERSION := v1.3.2

UNAME_OS := $(shell uname -s)
UNAME_ARCH := $(shell uname -m)
ifeq ($(UNAME_OS),Darwin)
	PLATFORM := osx
endif
ifeq ($(UNAME_OS),Linux)
	PLATFORM := linux
endif

# Buf will be cached to ~/.cache/buf-example.
CACHE_BASE := $(HOME)/.cache/$(PROJECT)
# This allows switching between i.e a Docker container and your local setup without overwriting.
CACHE := $(CACHE_BASE)/$(UNAME_OS)/$(UNAME_ARCH)
# The location where buf will be installed.
CACHE_BIN := $(CACHE)/bin
# Marker files are put into this directory to denote the current version of binaries that are installed.
CACHE_VERSIONS := $(CACHE)/versions

# Update the $PATH so we can use buf directly
export PATH := $(abspath $(CACHE_BIN)):$(PATH)


# BUF points to the marker file for the installed version.
#
# If BUF_VERSION is changed, the binary will be re-downloaded.
BUF := $(CACHE_VERSIONS)/buf/$(BUF_VERSION)
$(BUF):
	@rm -f $(CACHE_BIN)/buf
	@mkdir -p $(CACHE_BIN)
	curl -sSL \
		"https://github.com/bufbuild/buf/releases/download/v$(BUF_VERSION)/buf-$(UNAME_OS)-$(UNAME_ARCH)" \
		-o "$(CACHE_BIN)/buf"
	chmod +x "$(CACHE_BIN)/buf"

	@rm -rf $(dir $(BUF))
	@mkdir -p $(dir $(BUF))
	@touch $(BUF)
# PROTOC_GEN_GO points to the marker file for the installed version.
#
# If PROTOC_GEN_GO_VERSION is changed, the binary will be re-downloaded.
PROTOC_GEN_GO := $(CACHE_VERSIONS)/protoc-gen-go/$(PROTOC_GEN_GO_VERSION)
$(PROTOC_GEN_GO):
	@rm -f $(CACHE_BIN)/protoc-gen-go
	@mkdir -p $(CACHE_BIN)
	$(eval PROTOC_GEN_GO_TMP := $(shell mktemp -d))
	cd $(PROTOC_GEN_GO_TMP); go install github.com/golang/protobuf/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	@rm -rf $(PROTOC_GEN_GO_TMP)
	@rm -rf $(dir $(PROTOC_GEN_GO))
	@mkdir -p $(dir $(PROTOC_GEN_GO))
	@touch $(PROTOC_GEN_GO)	

# PROTOC points to the marker file for the installed version.
#
# If PROTOC_VERSION is changed, the binary will be re-downloaded.
PROTOC := $(CACHE_VERSIONS)/protoc/$(PROTOC_VERSION)
$(PROTOC):
	@rm -f $(CACHE_BIN)/protoc
	@mkdir -p $(CACHE_BIN)
	$(eval PROTOC_TMP := $(shell mktemp -d))
	curl -sSL \
		"https://github.com/protocolbuffers/protobuf/releases/download/v$(PROTOC_VERSION)/protoc-$(PROTOC_VERSION)-$(PLATFORM)-$(UNAME_ARCH).zip" \
		-o "$(PROTOC_TMP)/protoc.zip"
	unzip -o "$(PROTOC_TMP)/protoc.zip" -d "$(CACHE)" bin/protoc
	unzip -o "$(PROTOC_TMP)/protoc.zip" -d "$(CACHE)" include/*
	@rm -rf $(PROTOC_TMP)
	chmod +x "$(CACHE_BIN)/protoc"
	@rm -rf $(dir $(PROTOC))
	@mkdir -p $(dir $(PROTOC))
	@touch $(PROTOC)


.PHONY: genprotos
genprotos: $(BUF) $(PROTOC) $(PROTOC_GEN_GO) 
	buf generate --template buf.gen.yaml	

