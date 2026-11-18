include $(TOPDIR)/rules.mk

PKG_NAME:=xkeenwrt-core
PKG_VERSION:=0.1.26.3
PKG_RELEASE:=0
PKG_LICENSE:=MIT AND GPL-3.0-only
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
include $(INCLUDE_DIR)/package.mk

define Package/xkeenwrt-core
  SECTION:=net
  CATEGORY:=Network
  TITLE:=XkeenWRT validator and recovery with managed Mihomo release catalogue
  DEPENDS:=+libc +procd
endef

define Package/xkeenwrt-core/description
  Independent validation and recovery helpers; Mihomo is installed and updated through the trusted UI release manager.
endef

define Build/Prepare
	[ -n "$(XKEENWRT_STAGE)" ]
	[ "$$(cat '$(XKEENWRT_STAGE)/ARCH')" = "$(ARCH_PACKAGES)" ]
	[ "$$(cat '$(XKEENWRT_STAGE)/VERSION')" = "$(PKG_VERSION)-r$(PKG_RELEASE)" ]
	cd '$(XKEENWRT_STAGE)' && sha256sum -c MANIFEST.sha256
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Compile
endef

define Package/xkeenwrt-core/install
	$(CP) $(XKEENWRT_STAGE)/core/. $(1)/
	rm -f $(1)/lib/apk/packages/xkeenwrt-core.list
endef

define Package/xkeenwrt-core/preinst
[ "$${PKG_UPGRADE}" != 1 ] || [ -n "$${IPKG_INSTROOT}" ] || /usr/libexec/xkeenwrt/package-hook-core upgrade core
endef

define Package/xkeenwrt-core/postinst
[ -n "$${IPKG_INSTROOT}" ] || /usr/libexec/xkeenwrt/package-hook-core install core
endef

define Package/xkeenwrt-core/prerm
[ -n "$${IPKG_INSTROOT}" ] || /usr/libexec/xkeenwrt/package-hook-core remove core
endef

$(eval $(call BuildPackage,xkeenwrt-core))
