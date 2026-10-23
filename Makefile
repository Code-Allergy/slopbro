# SlopBro
# by throwaway96
# https://github.com/throwaway96/slopbro
# Copyright 2026. Licensed under AGPL v3 or later. No warranties.

INPUT_SCRIPT = slopbro.py
WWWROOT_FILES = index.html autoroot.sh package.json main.js luna-helper.js hbchannel-startup.sh
PACKED_FILE = dist/slopbro_packed.py

PACKAGING_TOOL = tools/package_single_file.py

.PHONY: all
all: dist

.PHONY: dist
dist: $(PACKAGING_TOOL) $(INPUT_SCRIPT) $(addprefix wwwroot/, $(WWWROOT_FILES))
	python3 '$(PACKAGING_TOOL)' --source '$(INPUT_SCRIPT)' --files $(WWWROOT_FILES) --out '$(PACKED_FILE)'

.PHONY: clean
clean:
	rm -rf -- 'dist/'

.PHONY: test
test:
	python3 -m unittest discover -s tests -v
	node tests/test_payload.js
	python3 -m py_compile slopbro.py tools/package_single_file.py
	node --check wwwroot/main.js
	node --check wwwroot/luna-helper.js
	bash -n wwwroot/autoroot.sh wwwroot/hbchannel-startup.sh
