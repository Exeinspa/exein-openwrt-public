#
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

LIB_MENU:=Libraries

define KernelPackage/exein
  SUBMENU:=$(LIB_MENU)
  TITLE:=Exein interface
  KCONFIG:=CONFIG_EXEIN_INTERFACE
  FILES:= $(LINUX_DIR)/drivers/exein_interface/exein_interface.ko
endef

define KernelPackage/exein/description
 Kernel modules for Exein interface
endef

$(eval $(call KernelPackage,exein))
