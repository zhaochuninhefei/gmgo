# Makefile
include buildignore.mk

.PHONY: all clean help

all:
	@echo "Building packages..."
	@go list ./... | grep -vE "$(EXCLUDE_MODULES)" | xargs go build

clean:
	@echo "Cleaning up..."
	@rm -rf ./bin ./pkg

help:
	@echo "Makefile for Go project"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build all packages except those matching patterns in .buildignore.mk"
	@echo "  clean     - Remove binary and package files"
	@echo "  help      - Show this help message"
