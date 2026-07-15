# Makefile — build, test, coverage gate for the hath Go port.

GOFLAGS := -trimpath
PKG     := ./internal/hath
GATE    := 80   # minimum coverage % enforced by `make gate`

.PHONY: all build test vet cover gate ci clean

all: build

build:
	go build $(GOFLAGS) ./...

test:
	go test $(PKG) -count=1

vet:
	go vet ./...

# Run tests with coverage and print a per-file breakdown.
cover:
	go test $(PKG) -coverprofile=cover.out -count=1
	@go tool cover -func=cover.out | tail -1
	@echo "-- per file --"
	@awk '/github.com.*\.go:/{split($$1,a,":");file=a[1];sub(/.*\//,"",file);total[file]+=$$2;if($$3+0>0)covered[file]+=$$2}END{for(f in total)printf "%-14s %3d%%\n",f,100*covered[f]/total[f]}' cover.out | sort -k2 -n

# Enforce the coverage gate. Fails (exit 1) if total < $(GATE)%.
gate:
	@go test $(PKG) -coverprofile=cover.out -count=1 >/dev/null 2>&1
	@pct=$$(go tool cover -func=cover.out | awk '/^total/{gsub(/%/,"",$$3); split($$3,a,".");print a[1]}'); \
	echo "coverage: $$pct% (gate: $(GATE)%)"; \
	if [ "$$pct" -lt $(GATE) ]; then \
	  echo "FAIL: coverage $$pct% below gate $(GATE)%"; exit 1; \
	fi; \
	echo "OK: coverage gate passed"

# Full CI sequence.
ci: vet test gate

clean:
	rm -f cover.out cover.html
