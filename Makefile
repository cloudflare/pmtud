pmtud:
	ninja -C build

clean:
	ninja -C build clean

install:
	DESTDIR=$(DESTDIR) ninja -C build install

dist:
	ninja -C build dist

check:
	ninja -C build test

format:
	clang-format -i src/*.c src/*.h

# Release process
# ---------------
PREV_VERSION := $(shell git describe --abbrev=0 --tags)
NEXT_VERSION := v$(shell echo $(PREV_VERSION) | tr -d v | awk '{print $$1+0.1}')

.PHONY: release

release:
	@echo "[*] Curr version: $(shell git describe --tags)"
	@echo "[*] Next version: $(NEXT_VERSION)"
	echo "$(NEXT_VERSION)  (`date '+%Y%m%d-%H%M'`)" > RELEASE_NOTES.tmp
	git log --reverse --date=short --format="- %ad %s" tags/$(PREV_VERSION)..HEAD >> RELEASE_NOTES.tmp
	echo "" >> RELEASE_NOTES.tmp
	cat RELEASE_NOTES >> RELEASE_NOTES.tmp
	mv RELEASE_NOTES.tmp RELEASE_NOTES
	git add RELEASE_NOTES
	git commit -m "Release $(NEXT_VERSION)"
	git tag $(NEXT_VERSION)
	@echo "[*] To push the release run:"
	@echo "git push origin master && git push origin $(NEXT_VERSION)"

# Build process
# -------------
BIN_PREFIX   ?= /usr/local/bin
PACKAGE_ROOT := $(shell pwd)/tmp/packaging

.PHONY: print-builddeps cf-package

CFDEPENDENCIES = gcc make pkg-config meson

print-builddeps:
	@echo $(CFDEPENDENCIES) $(DEPENDENCIES)

cf-package:
	@echo "[*] rebuilding"
	-$(MAKE) clean
	$(MAKE) pmtud
	-mkdir -p $(PACKAGE_ROOT)/$(BIN_PREFIX)
	cp build/pmtud $(PACKAGE_ROOT)/$(BIN_PREFIX)
	fakeroot fpm -C $(PACKAGE_ROOT) \
		-s dir \
		-t deb \
		--deb-compression bzip2 \
		-v $(VERSION) \
		--iteration $(ITERATION) \
		-n pmtud \
		.
	rm -rf $(PACKAGE_ROOT)
