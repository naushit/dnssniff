# OpenWrt package recipe for dnssniff

include $(TOPDIR)/rules.mk

PKG_NAME:=dnssniff
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/naushit/dnssniff.git
PKG_SOURCE_VERSION:=c57080aac37a71bd1bf956ee58b6aa4ab622acdd

PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/rust-package.mk

define Package/dnssniff
  SECTION:=net
  CATEGORY:=Network
  TITLE:=dnssniff - Lightweight DNS Sniffer for OpenWrt
  URL:=https://github.com/naushit/dnssniff
  DEPENDS:=@TARGET_* +kmod-ipt-core
endef

define Package/dnssniff/description
  Lightweight, zero-persistence DNS packet sniffer and diagnostic telemetry
  tool for OpenWrt routers. Uses native Linux AF_PACKET raw sockets with
  in-kernel cBPF filtering (no libpcap dependency). Provides an embedded
  web dashboard at port 9153 with Server-Sent Events telemetry.
endef

define Package/dnssniff/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/target/*/release/dnssniff $(1)/usr/bin/dnssniff
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/dnssniff.config $(1)/etc/config/dnssniff
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/dnssniff.init $(1)/etc/init.d/dnssniff
endef

define Package/dnssniff/postinst
#!/bin/sh
# Enable and start dnssniff via procd
/etc/init.d/dnssniff enable
/etc/init.d/dnssniff start
endef

$(eval $(call RustPackage,dnssniff))
