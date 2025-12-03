# PuraDNS Makefile

# Variables
BINARY_NAME := puradns
CONFIG_DIR := /etc/puradns
CONFIG_FILE := $(CONFIG_DIR)/puradns.yaml
RULES_DIR := $(CONFIG_DIR)/rules
CHINA_IP_FILE := $(RULES_DIR)/china-ip.txt
CHINA_LIST_FILE := $(RULES_DIR)/chinalist.txt
GFW_LIST_FILE := $(RULES_DIR)/gfwlist.txt
SYSTEMD_SERVICE_FILE := /etc/systemd/system/$(BINARY_NAME).service

# Default target
all: build

# Build the binary
build:
	go build -o $(BINARY_NAME) .

# Cross-compile for ARM architectures
# Build for ARM 64-bit (arm64)
build-arm64:
	GOOS=linux GOARCH=arm64 go build -o $(BINARY_NAME)-arm64 .

# Build for ARM 32-bit (armv7)
build-armv7:
	GOOS=linux GOARCH=arm GOARM=7 go build -o $(BINARY_NAME)-armv7 .

# Build for all supported ARM architectures
build-all-arm:
	make build-arm64 build-armv7

# Clean all builds
clean-all:
	rm -f $(BINARY_NAME) $(BINARY_NAME)-arm64 $(BINARY_NAME)-armv7

# Install the service
install:
	# Create configuration directory
	mkdir -p $(CONFIG_DIR)
	mkdir -p $(RULES_DIR)
	
	# Copy default configuration if not exists
	if [ ! -f $(CONFIG_FILE) ]; then \
		cp puradns.yaml $(CONFIG_FILE); \
	fi
	
	# Copy rule files
	cp /home/china-ip.txt $(CHINA_IP_FILE)
	cp /home/chinalist.txt $(CHINA_LIST_FILE)
	cp /home/gfwlist.txt $(GFW_LIST_FILE)
	
	# Set proper permissions
	chmod 644 $(CONFIG_FILE)
	chmod 644 $(CHINA_IP_FILE)
	chmod 644 $(CHINA_LIST_FILE)
	chmod 644 $(GFW_LIST_FILE)
	
	# Copy binary to /usr/local/bin
	cp $(BINARY_NAME) /usr/local/bin/
	chmod 755 /usr/local/bin/$(BINARY_NAME)
	
	# Create systemd service file
	echo '[Unit]' > $(SYSTEMD_SERVICE_FILE)
	echo 'Description=PuraDNS - A DNS server with GFW detection and caching' >> $(SYSTEMD_SERVICE_FILE)
	echo 'After=network.target' >> $(SYSTEMD_SERVICE_FILE)
	echo '' >> $(SYSTEMD_SERVICE_FILE)
	echo '[Service]' >> $(SYSTEMD_SERVICE_FILE)
	echo 'Type=simple' >> $(SYSTEMD_SERVICE_FILE)
	echo 'ExecStart=/usr/local/bin/$(BINARY_NAME) -config $(CONFIG_FILE)' >> $(SYSTEMD_SERVICE_FILE)
	echo 'Restart=on-failure' >> $(SYSTEMD_SERVICE_FILE)
	echo 'RestartSec=5s' >> $(SYSTEMD_SERVICE_FILE)
	echo 'User=root' >> $(SYSTEMD_SERVICE_FILE)
	echo 'Group=root' >> $(SYSTEMD_SERVICE_FILE)
	echo '' >> $(SYSTEMD_SERVICE_FILE)
	echo '[Install]' >> $(SYSTEMD_SERVICE_FILE)
	echo 'WantedBy=multi-user.target' >> $(SYSTEMD_SERVICE_FILE)
	
	# Set proper permissions for systemd service file
	chmod 644 $(SYSTEMD_SERVICE_FILE)
	
	# Reload systemd daemon
	systemctl daemon-reload
	
	@echo "PuraDNS installed successfully!"
	@echo "Configuration file: $(CONFIG_FILE)"
	@echo "Rule files: $(RULES_DIR)/"
	@echo "Systemd service: $(SYSTEMD_SERVICE_FILE)"
	@echo "To start the service: systemctl start $(BINARY_NAME)"
	@echo "To enable the service on boot: systemctl enable $(BINARY_NAME)"

# Clean the build
clean:
	rm -f $(BINARY_NAME)

# Uninstall the service
uninstall:
	# Stop and disable the service
	systemctl stop $(BINARY_NAME) 2>/dev/null || true
	systemctl disable $(BINARY_NAME) 2>/dev/null || true
	
	# Remove systemd service file
	rm -f $(SYSTEMD_SERVICE_FILE)
	
	# Reload systemd daemon
	systemctl daemon-reload
	
	# Remove binary
	rm -f /usr/local/bin/$(BINARY_NAME)
	
	# Remove configuration directory
	rm -rf $(CONFIG_DIR)
	
	@echo "PuraDNS uninstalled successfully!"

.PHONY: all build install clean uninstall

# Build DEB package for ARM64
build-deb-arm64:
	@echo "Building DEB package for ARM64..."
	mkdir -p /tmp/debian/DEBIAN /tmp/debian/usr/local/bin /tmp/debian/etc/puradns/rules /tmp/debian/etc/systemd/system
	cat debian/DEBIAN/control > /tmp/debian/DEBIAN/control
	cat debian/DEBIAN/postinst > /tmp/debian/DEBIAN/postinst
	cat debian/DEBIAN/prerm > /tmp/debian/DEBIAN/prerm
	cat debian/DEBIAN/postrm > /tmp/debian/DEBIAN/postrm
	chmod 755 /tmp/debian/DEBIAN/postinst /tmp/debian/DEBIAN/prerm /tmp/debian/DEBIAN/postrm
	cp puradns-arm64 /tmp/debian/usr/local/bin/puradns
	cp puradns.yaml /tmp/debian/etc/puradns/puradns.yaml
	cp /home/china-ip.txt /home/chinalist.txt /home/gfwlist.txt /tmp/debian/etc/puradns/rules/
	cp debian/puradns.service /tmp/debian/etc/systemd/system/puradns.service
	dpkg-deb --build /tmp/debian /tmp/puradns-arm64.deb
	@echo "DEB package built successfully: /tmp/puradns-arm64.deb"
	@echo "To install: dpkg -i /tmp/puradns-arm64.deb"
	@echo "To uninstall: dpkg -r puradns"

