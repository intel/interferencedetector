PACKAGE_EXTERNAL := procmon.tgz
default: dist
.PHONY: default dist format format_check style_error_check check


dist/$(PACKAGE_EXTERNAL): procmon/procmon.py procmon/dockermon.py procmon/events.yaml procmon/NN_detect.py README.md LICENSE requirements.txt
	rm -rf dist
	rm -rf build
	mkdir -p dist
	mkdir -p build/procmon
	cp procmon/procmon.py procmon/dockermon.py procmon/events.yaml procmon/NN_detect.py README.md LICENSE requirements.txt build/procmon/
	cd build && tar -czf ../dist/procmon.tgz procmon/*
	rm -rf build

format_check:
	black --check procmon

format:
	black procmon

style_error_check:
	# ignore long lines and conflicts with black, i.e., black wins
	flake8 procmon --ignore=E501,W503,E203

check: format_check style_error_check

dist: check dist/$(PACKAGE_EXTERNAL) 