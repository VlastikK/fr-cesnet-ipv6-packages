
include $(TOPDIR)/rules.mk

PKG_NAME:=tl-wdr4300-usb-opt
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_MAINTAINER:=Vlastimil Kosar <ikosar@fit.vutbr.cz>
PKG_LICENSE:=FIT

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/tl-wdr4300-usb-opt
  SUBMENU:=CESNET FR
  SECTION:=net
  CATEGORY:=Network
  TITLE:=tl-wdr4300-usb-opt
  DEPENDS:=+kmod-usb-storage +kmod-usb-storage-extras +kmod-fs-vfat +kmod-nls-cp437 +kmod-nls-iso8859-1 +kmod-loop +kmod-fs-ext4 +losetup
endef

define Package/tl-wdr4300-usb-opt/description
	Mounts file containing ext3 FS located on usb disk to /opt and sets correctly paths.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -r ./files/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	
endef

define Package/tl-wdr4300-usb-opt/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tl-wdr4300-usb-opt.init $(1)/etc/init.d/tl-wdr4300-usb-opt
	$(INSTALL_DIR) $(1)/etc/rc.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tl-wdr4300-usb-opt.init $(1)/etc/rc.d/S98tl-wdr4300-usb-opt
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tl-wdr4300-usb-opt.init $(1)/etc/rc.d/K98tl-wdr4300-usb-opt
	$(INSTALL_DIR) $(1)/usr/share
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tl-wdr4300-usb-opt.tmpl $(1)/usr/share/tl-wdr4300-usb-opt.tmpl
endef

$(eval $(call BuildPackage,tl-wdr4300-usb-opt))
