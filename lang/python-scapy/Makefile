
include $(TOPDIR)/rules.mk

PKG_NAME:=python-scapy
PKG_VERSION:=2.3.2
PKG_RELEASE:=1
PKG_MAINTAINER:=Vlastimil Kosar <ikosar@fit.vutbr.cz>
PKG_LICENSE:=GPLv2

PKG_SOURCE:=scapy-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://pypi.python.org/packages/source/s/scapy/
PKG_MD5SUM:=b8ca06ca3b475bd01ba6cf5cdc5619af

PKG_BUILD_DIR:=$(BUILD_DIR)/scapy-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=python

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/python-scapy
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=python-scapy
  URL:=http://www.secdev.org/projects/scapy
  DEPENDS:=+python +tcpdump
endef

define Package/python-scapy/description
	Scapy - interactive packet manipulation tool
endef

define Build/Compile
	$(call Build/Compile/PyMod,,install --prefix="$(PKG_INSTALL_DIR)/usr")
endef

define Package/python-scapy/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR) $(1)/usr/bin $(1)/usr/share
	$(CP) \
	    $(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
	    $(1)$(PYTHON_PKG_DIR)
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/* $(1)/usr/bin
	$(CP) -r $(PKG_INSTALL_DIR)/usr/share/* $(1)/usr/share
	
endef

$(eval $(call BuildPackage,python-scapy))
