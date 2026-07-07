APP_NAME = pretty-verifier
INSTALL_DIR = /opt/$(APP_NAME)
BIN_SYMLINK = /usr/local/bin/$(APP_NAME)
VENV = $(INSTALL_DIR)/venv

LIB_SRC_DIR = lib
BUILD_DIR = build

.PHONY: all install install-cli install-lib uninstall clean

all: install

install-cli:
	@echo "--- Installing Pretty Verifier CLI ---"
	# Clean and create directory
	sudo rm -rf $(INSTALL_DIR)
	sudo mkdir -p $(INSTALL_DIR)
	
	# Create venv and install package
	sudo python3 -m venv $(VENV)
	sudo $(VENV)/bin/pip install --upgrade pip
	sudo $(VENV)/bin/pip install .
	
	# Symlink to global path
	sudo ln -sf $(VENV)/bin/$(APP_NAME) $(BIN_SYMLINK)
	@echo "--- Pretty Verifier CLI Installed ---"

install-lib:
	@echo "--- Building and Installing C Library ---"
	# Create build directory
	mkdir -p $(BUILD_DIR)
	
	# Configure CMake
	cd $(BUILD_DIR) && cmake ../$(LIB_SRC_DIR)
	
	# Compile
	cd $(BUILD_DIR) && make
	
	# Install system-wide
	cd $(BUILD_DIR) && sudo make install
	
	# Update library cache
	sudo ldconfig
	@echo "--- C Library Installed ---"

install: install-cli install-lib
	@echo "--- Full Installation Complete ---"

uninstall:
	@echo "--- Uninstalling ---"
	sudo rm -rf $(INSTALL_DIR)
	sudo rm -f $(BIN_SYMLINK)
	sudo rm -f /usr/local/lib/libpretty-verifier.so
	sudo rm -f /usr/local/include/pretty_verifier.h
	sudo ldconfig
	@echo "--- Uninstalled ---"

# --- Clean ---
clean:
	rm -rf $(BUILD_DIR)
	rm -rf *.egg-info src/*.egg-info src/pretty_verifier/__pycache__