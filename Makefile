PODMAN ?= podman
DEB_DISTROS ?= ubuntu-24.04 ubuntu-26.04 debian-13

.PHONY: deb deb-build deb-test deb-lint deb-repro deb-ci deb-clean deb-help

deb: deb-build deb-test deb-lint

deb-build:
	dpkg-buildpackage -b -us -uc

deb-test:
	packaging/debian/test-installed.sh

deb-lint:
	set -eu; package=$$(ls -1t ../katzenpost-status_*_all.deb | head -1); \
	lintian --no-tag-display-limit "$$package"

deb-repro:
	packaging/debian/reproducible.sh

deb-ci: deb-build deb-test deb-lint deb-repro

deb-clean:
	dh_clean
	rm -f ../katzenpost-status_*.deb ../katzenpost-status_*.changes \
		../katzenpost-status_*.buildinfo

deb-help:
	@echo 'make deb-build  build the Debian package on this system'
	@echo 'make deb-test   exercise installed CLI and systemd units from the package'
	@echo 'make deb-lint   run lintian on the latest package'
	@echo 'make deb-repro  build twice in independent source trees and compare'
	@echo 'make deb-ci     run build, installed-package checks, lint and reproducibility'
	@echo 'make deb-clean  remove packaging products'
