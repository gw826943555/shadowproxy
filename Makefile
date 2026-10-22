#
# Copyright (C) 2016-2023 King <9566618@gmail.com>
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=shadowproxy
PKG_VERSION:=1.25.0
PKG_RELEASE:=1

PKG_LICENSE:=GPLv3
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=King <9566618@gmail.com>

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=VPN
	TITLE:=Shadowsocks-Rust TProxy
	URL:=https://github.com/shadowsocks/shadowsocks-rust
	DEPENDS:=+kmod-nft-tproxy +shadowsocks-rust-sslocal
endef

define Package/$(PKG_NAME)/description
	LuCI Support for shadowsocks-rust, and it automatically
	sets dns and nftables tproxy. It also supports ACL rules
	for controlling all net packets
endef

define Build/Compile
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/
	cp -pR ./root/* $(1)/
	$(INSTALL_DIR) $(1)/www
	cp -pR ./htdocs/* $(1)/www
endef

define Package/$(PKG_NAME)/postinst
[ -n "$${IPKG_INSTROOT}" ] || { \
	rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	killall -HUP rpcd 2>/dev/null
	exit 0
}
endef

$(eval $(call BuildPackage,$(PKG_NAME)))