
include $(TOPDIR)/rules.mk

PKG_NAME:=python-netifaces
PKG_VERSION:=0.10.4
PKG_RELEASE:=1
PKG_MAINTAINER:=Vlastimil Kosar <ikosar@fit.vutbr.cz>
PKG_LICENSE:=MIT License

PKG_SOURCE:=netifaces-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://pypi.python.org/packages/source/n/netifaces/
PKG_MD5SUM:=36da76e2cfadd24cc7510c2c0012eb1e

PKG_BUILD_DIR:=$(BUILD_DIR)/netifaces-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=python

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/python-netifaces
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=python-netifaces
  URL:=https://bitbucket.org/al45tair/netifaces
  DEPENDS:=+python +python-setuptools
endef

define Package/python-netifaces/description
	Portable network interface information.
endef

define Build/Compile
	$(call Build/Compile/PyMod,,install --prefix="$(PKG_INSTALL_DIR)/usr")
endef

define Package/python-netifaces/install
	unzip -o -q $(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/netifaces-0.10.4-py2.7-linux2.egg -d $(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)
	$(CP) \
	    $(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/netifaces.* \
	    $(1)$(PYTHON_PKG_DIR)
endef

$(eval $(call BuildPackage,python-netifaces))
