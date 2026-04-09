.PHONY: build build-linux clean test test-race deps ui-install ui-dev ui-build

BUILD_DIR    = ./build
UI_DIR       = ./ui
FRONTEND_DIST= ./frontend/dist
LDFLAGS      = -s -w

SERVICES = muvon muwaf dialog-siem agent

# ── Build (native) ──────────────────────────────────────────

build: ui-build
	@mkdir -p $(BUILD_DIR)
	@for svc in $(SERVICES); do \
		echo "Building $$svc..."; \
		CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$$svc ./cmd/$$svc; \
	done
	@echo "Done: $(BUILD_DIR)/"

# ── Build (minimal: muvon + agent only, no WAF/diaLOG) ─────

build-minimal: ui-build
	@mkdir -p $(BUILD_DIR)
	@for svc in muvon agent; do \
		echo "Building $$svc..."; \
		CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$$svc ./cmd/$$svc; \
	done
	@echo "Done: $(BUILD_DIR)/"

build-minimal-linux: ui-build
	@mkdir -p $(BUILD_DIR)
	@for svc in muvon agent; do \
		echo "Building $$svc (linux/amd64)..."; \
		GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" \
			-o $(BUILD_DIR)/$$svc-linux-amd64 ./cmd/$$svc; \
	done
	@echo "Done: $(BUILD_DIR)/"

# ── Build (Linux amd64 cross-compile) ──────────────────────

build-linux: ui-build
	@mkdir -p $(BUILD_DIR)
	@for svc in $(SERVICES); do \
		echo "Building $$svc (linux/amd64)..."; \
		GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" \
			-o $(BUILD_DIR)/$$svc-linux-amd64 ./cmd/$$svc; \
	done
	@echo "Done: $(BUILD_DIR)/"

# ── Clean ───────────────────────────────────────────────────

clean:
	rm -f $(BUILD_DIR)/muvon* $(BUILD_DIR)/muwaf* $(BUILD_DIR)/dialog-siem* $(BUILD_DIR)/agent*
	@echo "Build artifacts cleaned"

# ── Test ────────────────────────────────────────────────────

test:
	go test ./... -v -count=1

test-race:
	go test ./... -v -race -count=1

# ── Dependencies ────────────────────────────────────────────

deps:
	go mod tidy
	go mod download

# ── UI ──────────────────────────────────────────────────────

ui-install:
	cd $(UI_DIR) && npm install

ui-dev:
	cd $(UI_DIR) && npm run dev

ui-build:
	@if [ -d "$(UI_DIR)" ] && [ -f "$(UI_DIR)/package.json" ]; then \
		echo "Building UI..."; \
		npm --prefix $(UI_DIR) run build; \
		mkdir -p $(FRONTEND_DIST); \
		rm -rf $(FRONTEND_DIST)/*; \
		cp -r $(UI_DIR)/dist/* $(FRONTEND_DIST)/; \
	else \
		echo "UI directory not found, skipping UI build"; \
	fi
