# Makefile — build, test, coverage gate for the hath Go port.

GOFLAGS := -trimpath
PKG     := ./internal/hath

# Minimum coverage % enforced by `make gate`, computed AFTER excluding the
# files in COVERAGE_EXCLUDE: pure runtime/bootstrap glue that cannot be
# meaningfully unit-tested.
#   - lifecycle.go : os.Exit terminal handler (no testable return path)
#   - log.go       : init() fallback is unreachable (zap.NewDevelopment never
#                    fails); the rest is a thin zap wrapper.
GATE             := 85
COVERAGE_EXCLUDE := lifecycle.go log.go

.PHONY: all build test vet cover gate ci dist clean

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

# Enforce the coverage gate on the non-excluded surface. Excluded files are
# stripped from the profile before the percentage is computed. Fails if the
# result is below $(GATE)%. See COVERAGE.md for the exclusion rationale.
gate:
	@go test $(PKG) -coverprofile=cover.raw -count=1 >/dev/null 2>&1
	@awk 'BEGIN{n=split("$(COVERAGE_EXCLUDE)",ex," ");for(i=1;i<=n;i++)skip[ex[i]]=1} \
	      /^mode:/ {print; next} \
	      {f=$$1; sub(/.*\//,"",f); split(f,g,":"); if(!(g[1] in skip)) print}' cover.raw > cover.out
	@pct=$$(awk '/github.com.*\.go:/{total+=$$2; if($$3+0>0) covered+=$$2} END{printf "%d", (total>0? 100*covered/total : 0)+0.5}' cover.out); \
	echo "coverage: $$pct% (gate: $(GATE)%, excluded: $(COVERAGE_EXCLUDE))"; \
	if [ "$$pct" -lt $(GATE) ]; then \
	  echo "FAIL: coverage $$pct% below gate $(GATE)%"; exit 1; \
	fi; \
	echo "OK: coverage gate passed"

# Full CI sequence.
ci: vet test gate

# Cross-compile tools for Linux (amd64 + arm64).
dist:
	rm -rf dist && mkdir dist
	for arch in amd64 arm64; do \
	  for tool in captureproxy rpcverify; do \
	    GOOS=linux GOARCH=$$arch CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/$$tool-linux-$$arch ./tools/$$tool; \
	  done; \
	done; \
	ls -lh dist/

clean:
	rm -f cover.out cover.raw cover.html
