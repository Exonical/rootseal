NAME    := rootseal
VERSION := 0.1.0
RELEASE := 1
DIST    := $(shell rpm --eval '%{?dist}' 2>/dev/null || echo .el10)

GOFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"
GOOS    ?= linux
GOARCH  ?= amd64

RPMBUILD_DIR := $(HOME)/rpmbuild

.PHONY: all build build-fips vendor rpm rpm-fips srpm clean test lint

all: build

# ── Go build ──────────────────────────────────────────────────────────────────
build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
	  go build $(GOFLAGS) -o bin/rootseal ./cmd/rootseal
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
	  go build $(GOFLAGS) -o bin/rootseal-controlplane ./cmd/controlplane

# ── FIPS build (BoringCrypto, requires CGO + gcc) ─────────────────────────────
build-fips:
	GOEXPERIMENT=boringcrypto CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) \
	  go build $(GOFLAGS) -o bin/rootseal-fips ./cmd/rootseal
	GOEXPERIMENT=boringcrypto CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) \
	  go build $(GOFLAGS) -o bin/rootseal-controlplane-fips ./cmd/controlplane
	@echo "FIPS binaries built. Verifying BoringCrypto via build metadata..."
	@go version -m bin/rootseal-fips | grep -q "boringcrypto" && \
	  echo "  rootseal-fips: BoringCrypto verified" || \
	  (echo "  ERROR: BoringCrypto not found in rootseal-fips" && exit 1)
	@go version -m bin/rootseal-controlplane-fips | grep -q "boringcrypto" && \
	  echo "  rootseal-controlplane-fips: BoringCrypto verified" || \
	  (echo "  ERROR: BoringCrypto not found in rootseal-controlplane-fips" && exit 1)

# ── Vendor ────────────────────────────────────────────────────────────────────
vendor:
	go mod tidy
	go mod vendor

# ── RPM ───────────────────────────────────────────────────────────────────────
rpm: vendor
	rpmdev-setuptree
	tar --transform 's,^,$(NAME)-$(VERSION)/,' \
	    --exclude='.git' \
	    --exclude='bin' \
	    --exclude='$(NAME)-$(VERSION)' \
	    -czf $(RPMBUILD_DIR)/SOURCES/$(NAME)-$(VERSION).tar.gz .
	cp packaging/rootseal.spec $(RPMBUILD_DIR)/SPECS/rootseal.spec
	rpmbuild -ba \
	    --define "_topdir $(RPMBUILD_DIR)" \
	    $(RPMBUILD_DIR)/SPECS/rootseal.spec
	@echo ""
	@echo "RPMs built:"
	@find $(RPMBUILD_DIR)/RPMS -name '*.rpm' -newer packaging/rootseal.spec

rpm-fips: vendor
	rpmdev-setuptree
	tar --transform 's,^,$(NAME)-$(VERSION)/,' \
	    --exclude='.git' \
	    --exclude='bin' \
	    -czf $(RPMBUILD_DIR)/SOURCES/$(NAME)-$(VERSION).tar.gz .
	cp packaging/rootseal.spec $(RPMBUILD_DIR)/SPECS/rootseal.spec
	rpmbuild -ba \
	    --define "_topdir $(RPMBUILD_DIR)" \
	    --with fips_build \
	    $(RPMBUILD_DIR)/SPECS/rootseal.spec
	@echo ""
	@echo "FIPS RPMs built:"
	@find $(RPMBUILD_DIR)/RPMS -name '*fips*.rpm' -newer packaging/rootseal.spec

srpm: vendor
	rpmdev-setuptree
	tar --transform 's,^,$(NAME)-$(VERSION)/,' \
	    --exclude='.git' \
	    --exclude='bin' \
	    -czf $(RPMBUILD_DIR)/SOURCES/$(NAME)-$(VERSION).tar.gz .
	cp packaging/rootseal.spec $(RPMBUILD_DIR)/SPECS/rootseal.spec
	rpmbuild -bs \
	    --define "_topdir $(RPMBUILD_DIR)" \
	    $(RPMBUILD_DIR)/SPECS/rootseal.spec

# ── Test / Lint ───────────────────────────────────────────────────────────────
test:
	go test ./internal/...

lint:
	golangci-lint run ./...
	gosec -exclude-dir pkg/api ./...

clean:
	rm -rf bin/ vendor/
