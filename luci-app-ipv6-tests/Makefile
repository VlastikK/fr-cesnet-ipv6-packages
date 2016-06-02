include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-ipv6-tests
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_MAINTAINER:=Jan Drazil <xdrazi00@stud.fit.vutbr.cz>
PKG_LICENSE:=FIT


PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-ipv6-tests
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=IPv6 Tests
  DEPENDS:=+luci-mod-admin-full +ipv6-attacks
  MAINTAINER:=Jan Drazil <xdrazi00@stud.fit.vutbr.cz>
endef

define Package/luci-app-ipv6-tests/description
 This package will install IPv6 Tests Web UI.
endef

define Build/Prepare
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/luci-app-ipv6-tests/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller/
	$(INSTALL_BIN) \
		./luasrc/controller/ipv6_security_tests.lua \
		$(1)/usr/lib/lua/luci/controller/ipv6_security_tests.lua

	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/
	$(INSTALL_BIN) -d \
		$(1)/usr/lib/lua/luci/view/ipv6_security_tests

	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/ipv6_security_tests/
	$(INSTALL_BIN) \
		./luasrc/view/ipv6_security_tests/ncp.htm \
		$(1)/usr/lib/lua/luci/view/ipv6_security_tests/ncp.htm

	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/ipv6_security_tests/
	$(INSTALL_BIN) \
		./luasrc/view/ipv6_security_tests/result.htm \
		$(1)/usr/lib/lua/luci/view/ipv6_security_tests/result.htm

	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/ipv6_security_tests/
	$(INSTALL_BIN) \
		./luasrc/view/ipv6_security_tests/rra.htm \
		$(1)/usr/lib/lua/luci/view/ipv6_security_tests/rra.htm
		
	$(INSTALL_DIR) $(1)/www/luci-static/resources/ipv6-attacks-icons/
	$(INSTALL_BIN) \
		./htdocs/luci-static/resources/ipv6-attacks-icons/secured.png \
		$(1)/www/luci-static/resources/ipv6-attacks-icons/secured.png	
	$(INSTALL_BIN) \
		./htdocs/luci-static/resources/ipv6-attacks-icons/unsecured.png \
		$(1)/www/luci-static/resources/ipv6-attacks-icons/unsecured.png
	
endef

$(eval $(call BuildPackage,luci-app-ipv6-tests))
