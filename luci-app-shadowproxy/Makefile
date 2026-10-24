#
# Copyright (C) 2016-2023 King <9566618@gmail.com>
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for shadowsocks-rust TProxy
LUCI_DESCRIPTION:=Web interface for shadowproxy: basic settings, proxy behavior, nodes and rules.
LUCI_DEPENDS:=+shadowproxy
LUCI_PKGARCH:=all

PKG_VERSION:=1.25.0
PKG_RELEASE:=1

PKG_LICENSE:=GPL-3.0-only
PKG_MAINTAINER:=King <9566618@gmail.com>

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
