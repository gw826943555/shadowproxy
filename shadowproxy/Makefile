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

PKG_LICENSE:=GPL-3.0-only
PKG_MAINTAINER:=King <9566618@gmail.com>

include $(INCLUDE_DIR)/package.mk

define Package/shadowproxy
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=VPN
	TITLE:=Shadowsocks-Rust TProxy service
	URL:=https://github.com/shadowsocks/shadowsocks-rust
	DEPENDS:=+kmod-nft-tproxy +nftables +ucode +ucode-mod-fs +ucode-mod-uci +shadowsocks-rust-sslocal
endef

define Package/shadowproxy/description
	Transparent proxy service built on shadowsocks-rust sslocal. It sets up
	nftables tproxy rules (rendered from ucode templates) and dnsmasq nftset
	entries for the configured domains, and supports ACL rules for controlling
	which traffic is proxied.
endef

define Package/shadowproxy/conffiles
/etc/config/shadowproxy
/etc/shadowproxy/shadowproxy-redir.acl
/etc/shadowproxy/bypass_ipset.acl
/etc/shadowproxy/proxy_domains.acl
endef

define Build/Compile
endef

define Package/shadowproxy/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/shadowproxy
	$(INSTALL_DIR) $(1)/usr/share/shadowproxy/ss-rules
	$(INSTALL_CONF) ./files/etc/config/shadowproxy $(1)/etc/config/shadowproxy
	$(INSTALL_BIN) ./files/etc/init.d/shadowproxy $(1)/etc/init.d/shadowproxy
	$(INSTALL_CONF) ./files/etc/shadowproxy/* $(1)/etc/shadowproxy/
	$(INSTALL_DATA) ./files/usr/share/shadowproxy/ss-rules/* $(1)/usr/share/shadowproxy/ss-rules/
endef

$(eval $(call BuildPackage,shadowproxy))
