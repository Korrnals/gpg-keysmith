.PHONY: build run test clean install install-go tidy vet fmt

BINARY := keysmith
BUILD_DIR := bin
CMD_DIR := ./cmd/keysmith

# Default install target: XDG user bin (no sudo, already in PATH on most
# Linux/macOS setups). Override with `make install INSTALL_DIR=/usr/local/bin`
# for a system-wide install (requires write access to that dir).
INSTALL_DIR ?= $(HOME)/.local/bin

.PHONY: default
default: build

## build: Compile + UPX-compress keysmith binary into ./bin
build:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "-s -w -X main.version=v$$(cat VERSION 2>/dev/null || echo dev)" -o $(BUILD_DIR)/$(BINARY) $(CMD_DIR)
	@if command -v upx >/dev/null 2>&1 && [ "$$(go env GOOS)" != "darwin" ]; then \
		upx -q --best $(BUILD_DIR)/$(BINARY) >/dev/null 2>&1 && echo "UPX compressed: $$(du -h $(BUILD_DIR)/$(BINARY) | cut -f1)" || echo "UPX skipped (unsupported)"; \
	fi

## run: Build and run keysmith with any args via ARGS=...
run: build
	./$(BUILD_DIR)/$(BINARY) $(ARGS)

## test: Run the test suite
test:
	go test ./...

## tidy: Run go mod tidy
tidy:
	go mod tidy

## vet: Run go vet
vet:
	go vet ./...

## fmt: Format all Go sources
fmt:
	go fmt ./...

## clean: Remove build artifacts
clean:
	rm -rf $(BUILD_DIR)

## install: Smart install — builds keysmith, installs to $(INSTALL_DIR)
## (default ~/.local/bin), checks/auto-installs gpg/git/gh, ensures
## $(INSTALL_DIR) is in PATH. Override INSTALL_DIR for system-wide installs.
## Runs user-space; deps that need root print the sudo command for you to run.
install: build
	@set -e; \
	INSTALL_DIR="$(INSTALL_DIR)"; \
	echo "==> Installing keysmith to $$INSTALL_DIR"; \
	mkdir -p "$$INSTALL_DIR"; \
	cp $(BUILD_DIR)/$(BINARY) "$$INSTALL_DIR/$(BINARY)"; \
	chmod +x "$$INSTALL_DIR/$(BINARY)"; \
	echo "✅ keysmith binary copied to $$INSTALL_DIR/$(BINARY)"; \
	\
	DEPS="gpg git gh"; \
	DEPS_STATUS=""; \
	for dep in $$DEPS; do \
		if command -v $$dep >/dev/null 2>&1; then \
			path=$$(command -v $$dep); \
			ver=""; \
			case $$dep in \
				gpg) ver=$$($$path --version 2>/dev/null | head -1);; \
				git) ver=$$($$path --version 2>/dev/null | head -1);; \
				gh)  ver=$$($$path --version 2>/dev/null | head -1);; \
			esac; \
			echo "✅ $$dep: $$path ($$ver)"; \
			DEPS_STATUS="$$DEPS_STATUS$$dep:✅;"; \
		else \
			echo "⚠️  $$dep not found — attempting auto-install"; \
			OS=$$(uname -s 2>/dev/null || echo unknown); \
			case $$OS in \
				Linux) \
					if command -v apt-get >/dev/null 2>&1; then \
						pkg="gnupg git gh"; \
						[ "$$dep" = "gh" ] && pkg="gh"; \
						[ "$$dep" = "gpg" ] && pkg="gnupg"; \
						[ "$$dep" = "git" ] && pkg="git"; \
						echo "  Trying apt-get (Debian/Ubuntu): sudo apt-get install -y $$pkg"; \
						if [ -w /var/lib/apt/lists ] || [ "$$(id -u)" = "0" ]; then \
							apt-get install -y $$pkg >/dev/null 2>&1 && echo "  ✅ $$dep installed via apt-get" || echo "  ❌ apt-get install failed — run manually: sudo apt-get install -y $$pkg"; \
						else \
							echo "  ⚠️  apt-get needs root. Run: sudo apt-get install -y $$pkg"; \
						fi;; \
					elif command -v dnf >/dev/null 2>&1; then \
						pkg="gnupg git gh"; \
						[ "$$dep" = "gh" ] && pkg="gh"; \
						[ "$$dep" = "gpg" ] && pkg="gnupg"; \
						[ "$$dep" = "git" ] && pkg="git"; \
						echo "  Trying dnf (Fedora): sudo dnf install -y $$pkg"; \
						if [ "$$(id -u)" = "0" ]; then \
							dnf install -y $$pkg >/dev/null 2>&1 && echo "  ✅ $$dep installed via dnf" || echo "  ❌ dnf install failed — run manually: sudo dnf install -y $$pkg"; \
						else \
							echo "  ⚠️  dnf needs root. Run: sudo dnf install -y $$pkg"; \
						fi;; \
					elif command -v pacman >/dev/null 2>&1; then \
						pkg="gnupg git github-cli"; \
						[ "$$dep" = "gh" ] && pkg="github-cli"; \
						[ "$$dep" = "gpg" ] && pkg="gnupg"; \
						[ "$$dep" = "git" ] && pkg="git"; \
						echo "  Trying pacman (Arch): sudo pacman -S --noconfirm $$pkg"; \
						if [ "$$(id -u)" = "0" ]; then \
							pacman -S --noconfirm $$pkg >/dev/null 2>&1 && echo "  ✅ $$dep installed via pacman" || echo "  ❌ pacman install failed — run manually: sudo pacman -S --noconfirm $$pkg"; \
						else \
							echo "  ⚠️  pacman needs root. Run: sudo pacman -S --noconfirm $$pkg"; \
						fi;; \
					else \
						case $$dep in \
							gpg) echo "  ❌ No package manager found. Install GnuPG manually: https://gnupg.org/download/";; \
							git) echo "  ❌ No package manager found. Install git manually: https://git-scm.com/downloads";; \
							gh)  echo "  ❌ No package manager found. Install GitHub CLI manually: https://cli.github.com/";; \
						esac;; \
					esac;; \
				Darwin) \
					if command -v brew >/dev/null 2>&1; then \
						pkg="gnupg git gh"; \
						[ "$$dep" = "gh" ] && pkg="gh"; \
						[ "$$dep" = "gpg" ] && pkg="gnupg"; \
						[ "$$dep" = "git" ] && pkg="git"; \
						echo "  Trying brew: brew install $$pkg"; \
						brew install $$pkg >/dev/null 2>&1 && echo "  ✅ $$dep installed via brew" || echo "  ❌ brew install failed — run manually: brew install $$pkg"; \
					else \
						echo "  ❌ Homebrew not found. Install it first: https://brew.sh, then: brew install gnupg git gh"; \
					fi;; \
				MINGW*|MSYS*|CYGWIN*) \
					case $$dep in \
						gpg) echo "  ❌ Windows: install GnuPG from https://gpg4win.org/ or run: winget install GnuPG.GnuPG";; \
						git) echo "  ❌ Windows: install git from https://git-scm.com/ or run: winget install Git.Git";; \
						gh)  echo "  ❌ Windows: install gh from https://cli.github.com/ or run: winget install GitHub.cli";; \
					esac;; \
				*) \
					echo "  ❌ Unsupported OS ($$OS). Install $$dep manually.";; \
			esac; \
			if command -v $$dep >/dev/null 2>&1; then \
				echo "✅ $$dep now available at $$(command -v $$dep)"; \
				DEPS_STATUS="$$DEPS_STATUS$$dep:✅;"; \
			else \
				echo "❌ $$dep still missing — install manually and re-run make install"; \
				DEPS_STATUS="$$DEPS_STATUS$$dep:❌;"; \
			fi; \
		fi; \
	done; \
	\
	echo "==> Ensuring $$INSTALL_DIR is in PATH"; \
	case ":$$PATH:" in \
		*":$$INSTALL_DIR:"*) echo "✅ $$INSTALL_DIR already in PATH";; \
		*) \
			SHELL_NAME="$${SHELL##*/}"; \
			case $$SHELL_NAME in \
				bash) RC_FILE="$$HOME/.bashrc"; LINE="export PATH=\"$$INSTALL_DIR:\$$PATH\"";; \
				zsh)  RC_FILE="$$HOME/.zshrc";  LINE="export PATH=\"$$INSTALL_DIR:\$$PATH\"";; \
				fish)  RC_FILE="$$HOME/.config/fish/config.fish"; LINE="set -gx PATH $$INSTALL_DIR \$$PATH";; \
				*)     RC_FILE="$$HOME/.bashrc"; LINE="export PATH=\"$$INSTALL_DIR:\$$PATH\""; echo "  (unknown shell $$SHELL_NAME, defaulting to ~/.bashrc)";; \
			esac; \
			mkdir -p "$$(dirname $$RC_FILE)"; \
			if [ -f "$$RC_FILE" ] && grep -q "$$INSTALL_DIR" "$$RC_FILE" 2>/dev/null; then \
				echo "✅ $$INSTALL_DIR already referenced in $$RC_FILE"; \
			else \
				printf '\n# Added by gpg-keysmith make install\n%s\n' "$$LINE" >> "$$RC_FILE"; \
				echo "⚠️  $$INSTALL_DIR added to $$RC_FILE. Restart your shell or run: source $$RC_FILE"; \
			fi;; \
	esac; \
	\
	echo "==> Verification"; \
	if "$$INSTALL_DIR/$(BINARY)" --version >/dev/null 2>&1; then \
		echo "✅ keysmith --version: $$("$$INSTALL_DIR/$(BINARY)" --version 2>&1 | head -1)"; \
	elif "$$INSTALL_DIR/$(BINARY)" --help >/dev/null 2>&1; then \
		echo "✅ keysmith --help runs successfully"; \
	else \
		echo "❌ keysmith binary failed to execute — check permissions and architecture"; \
		exit 1; \
	fi; \
	\
	echo ""; \
	echo "==> Summary"; \
	echo "| Component  | Status |"; \
	echo "|------------|--------|"; \
	echo "| keysmith   | ✅      |"; \
	for dep in gpg git gh; do \
		status=$$(echo "$$DEPS_STATUS" | tr ';' '\n' | grep "^$$dep:" | cut -d: -f2); \
		[ -z "$$status" ] && status="✅"; \
		printf "| %-10s | %s  |\n" "$$dep" "$$status"; \
	done; \
	echo ""; \
	echo "keysmith installed to $$INSTALL_DIR/$(BINARY)"; \
	[ -n "$$DEPS_STATUS" ] && echo "Note: some deps need a manual install (see messages above). Re-run 'make install' after installing them."

## install-go: Legacy Go-native install to $$GOBIN (or $$GOPATH/bin).
## Uses go install (no UPX/ldflags; targets GOBIN which may not be in PATH).
install-go:
	go install $(CMD_DIR)
# Local CI targets (gitignored) — billing-free replacement for GitHub Actions
-include Makefile.local
