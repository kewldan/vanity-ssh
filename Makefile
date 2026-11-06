METAL := Sources/VanitySSH/Metal/Kernel.metal
SWIFT_PATHS := Package.swift Sources Tests

.PHONY: build test lint format embed universal clean

build:
	swift build -c release

test:
	swift test

lint:
	swift format lint --strict --recursive $(SWIFT_PATHS)
	clang-format --style=file --dry-run --Werror $(METAL)
	scripts/embed-kernel.sh --check

format:
	swift format --in-place --recursive $(SWIFT_PATHS)
	clang-format --style=file -i $(METAL)
	scripts/embed-kernel.sh

embed:
	scripts/embed-kernel.sh

# Apple Silicon + Intel binary, as published in releases.
universal:
	swift build -c release --arch arm64 --arch x86_64
	@echo "$$(swift build -c release --arch arm64 --arch x86_64 --show-bin-path)/vanity-ssh"

clean:
	swift package clean
