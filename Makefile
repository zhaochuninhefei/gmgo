# Makefile
#EXCLUDE_MODULES := $(shell cat .buildignore | grep -v '^#' | paste -sd '|' -)
EXCLUDE_MODULES := $(shell cat .buildignore | paste -sd '|' -)
#EXCLUDE_MODULES_TEMP := $(shell cat .buildignore | grep -v '^#')
#EXCLUDE_MODULES := $(shell echo $(EXCLUDE_MODULES_TEMP) | paste -sd '|' -)
#EXCLUDE_MODULES := $(shell awk '!/^#/' .buildignore | paste -sd '|' -)

.PHONY: default all list liste showem help

default:
	@echo "Building packages with exclusions..."
	@go list ./... | grep -vE "$(EXCLUDE_MODULES)" | xargs go build

all:
	@echo "Building all packages..."
	@go list ./... | xargs go build

list:
	@echo "List all packages..."
	@go list ./...

liste:
	@echo "List packages with exclusions..."
	@go list ./... | grep -vE "$(EXCLUDE_MODULES)"

showem:
	@echo "Show EXCLUDE_MODULES:"
	@echo "$(EXCLUDE_MODULES)"

help:
	@echo "Makefile for Go project"
	@echo ""
	@echo "Targets:"
	@echo "  default   - Build packages except those matching patterns in .buildignore"
	@echo "  all       - Build all packages without any exclusions"
	@echo "  list      - List packages all"
	@echo "  liste     - List packages with exclusions"
	@echo "  showem    - Show EXCLUDE_MODULES"
	@echo "  help      - Show this help message"