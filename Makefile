.PHONY: build build-linux clean test test-race deps ui-install ui-dev ui-build

BUILD_DIR    = ./build
UI_DIR       = ./ui
FRONTEND_DIST= ./frontend/dist
LDFLAGS      = -s -w

SERVICES = muvon muwaf dialog-siem agent muvon-deployer

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

# ── Deploy to VPS ───────────────────────────────────────────

deploy: build-linux
	@echo "Deploying muvon to VPS..."
	@scp build/muvon-linux-amd64 vps:/opt/muvon/muvon
	@ssh vps "docker cp /opt/muvon/muvon muvon-muvon-1:/usr/local/bin/app && cd /opt/muvon && docker compose restart muvon"
	@echo "Done."

deploy-all: build-linux
	@echo "Deploying all services to VPS..."
	@scp build/muvon-linux-amd64 vps:/opt/muvon/muvon
	@scp build/muwaf-linux-amd64 vps:/opt/muvon/muwaf
	@ssh vps " \
		docker cp /opt/muvon/muvon muvon-muvon-1:/usr/local/bin/app && \
		docker cp /opt/muvon/muwaf muvon-muwaf-1:/usr/local/bin/app && \
		cd /opt/muvon && docker compose restart muwaf muvon"
	@echo "Done."

# Single-service quick deploys — handy while iterating on dialog-siem or
# muwaf without waiting for CI (each run is scp + docker cp + restart).
deploy-dialog:
	@echo "Building dialog-siem (linux/amd64)..."
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" \
		-o $(BUILD_DIR)/dialog-siem-linux-amd64 ./cmd/dialog-siem
	@scp $(BUILD_DIR)/dialog-siem-linux-amd64 vps:/opt/muvon/dialog-siem
	@ssh vps "docker cp /opt/muvon/dialog-siem muvon-dialog-siem-1:/usr/local/bin/app && cd /opt/muvon && docker compose restart dialog-siem"
	@echo "Done."

deploy-muwaf:
	@echo "Building muwaf (linux/amd64)..."
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" \
		-o $(BUILD_DIR)/muwaf-linux-amd64 ./cmd/muwaf
	@scp $(BUILD_DIR)/muwaf-linux-amd64 vps:/opt/muvon/muwaf
	@ssh vps "docker cp /opt/muvon/muwaf muvon-muwaf-1:/usr/local/bin/app && cd /opt/muvon && docker compose restart muwaf"
	@echo "Done."

deploy-deployer:
	@echo "Building muvon-deployer (linux/amd64)..."
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" \
		-o $(BUILD_DIR)/muvon-deployer-linux-amd64 ./cmd/muvon-deployer
	@scp $(BUILD_DIR)/muvon-deployer-linux-amd64 vps:/opt/muvon/muvon-deployer
	@ssh vps "docker cp /opt/muvon/muvon-deployer muvon-muvon-deployer-1:/usr/local/bin/app && cd /opt/muvon && docker compose restart muvon-deployer"
	@echo "Done."
