
include $(TOPDIR)/rules.mk

PKG_NAME:=ipv6-attacks
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_MAINTAINER:=Vlastimil Kosar <ikosar@fit.vutbr.cz>
PKG_LICENSE:=FIT

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=python

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/ipv6-attacks
  SUBMENU:=CESNET FR
  SECTION:=net
  CATEGORY:=Network
  TITLE:=ipv6-attacks
  DEPENDS:=+python +python-scapy +python-netifaces
endef

define Package/ipv6-attacks/description
	Tool for attacks on IPv6.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/*.py $(PKG_BUILD_DIR)/
endef

define Build/Compile
	
endef

define Package/ipv6-attacks/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ncp.py $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/rra.py $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wrapper.py $(1)/usr/bin
endef

$(eval $(call BuildPackage,ipv6-attacks))
