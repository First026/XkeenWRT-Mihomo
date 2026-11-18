include $(TOPDIR)/rules.mk

PKG_NAME:=xkeenwrt-ui
PKG_VERSION:=0.1.26.4
PKG_RELEASE:=0
PKG_LICENSE:=MIT
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
include $(INCLUDE_DIR)/package.mk

define Package/xkeenwrt-ui
  SECTION:=net
  CATEGORY:=Network
  TITLE:=XkeenWRT management UI
  DEPENDS:=+libc +procd +ca-bundle +ip-full +kmod-nft-tproxy +kmod-nft-socket +kmod-nf-conntrack-netlink +xkeenwrt-core
  EXTRA_DEPENDS:=xkeenwrt-core (= $(PKG_VERSION)-r$(PKG_RELEASE))
endef

define Package/xkeenwrt-ui/description
  XkeenWRT management UI and manual control runtime. Install starts only the UI and controller; Mihomo and network interception remain stopped.
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

define Package/xkeenwrt-ui/install
	$(CP) $(XKEENWRT_STAGE)/ui/. $(1)/
	rm -f $(1)/lib/apk/packages/xkeenwrt-ui.list
endef

define Package/xkeenwrt-ui/preinst
[ "$${PKG_UPGRADE}" != 1 ] || [ -n "$${IPKG_INSTROOT}" ] || /usr/libexec/xkeenwrt/package-hook-ui upgrade ui
endef

define Package/xkeenwrt-ui/postinst
[ -n "$${IPKG_INSTROOT}" ] || /usr/libexec/xkeenwrt/package-hook-ui install ui
endef

define Package/xkeenwrt-ui/prerm
[ -n "$${IPKG_INSTROOT}" ] || /usr/libexec/xkeenwrt/package-hook-ui remove ui
endef

$(eval $(call BuildPackage,xkeenwrt-ui))
