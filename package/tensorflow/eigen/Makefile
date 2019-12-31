include $(TOPDIR)/rules.mk

PKG_NAME:=eigen
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/eigenteam/eigen-git-mirror.git
PKG_SOURCE_VERSION:=115d7c7dfe67000660646f20fb74f8c65e05c539
PKG_MIRROR_HASH:=d03b89cbd6b4a1bd8bc57853368f019de52cefe00a4e2e6ef90f7633ef46c79f

PKG_LICENSE:=MPL2, BSD-3-Clause, LGPL-2.1
PKG_LICENSE_FILES:=COPYING.MPL2 COPYING.BSD COPYING.LGPL COPYING.README
PKG_MAINTAINER:=Exein <info@exein.io>

include $(INCLUDE_DIR)/package.mk


define Package/eigen
	SECTION:=libs
	CATEGORY:=Tensorflow
	SUBMENU:=Libraries
	TITLE:=C++ template library for linear algebra.
endef

define Build/Compile
endef

define Package/eigen/install
endef

define Build/InstallDev
	sed -r -e 's,^Version: .*,Version: $(PKG_VERSION),' \
		-e 's,^Cflags: .*,Cflags: -I$$\{prefix\}/include/eigen3,' \
		-e 's,^prefix.*,prefix=/usr,' \
		$(PKG_BUILD_DIR)/eigen3.pc.in >$(PKG_BUILD_DIR)/eigen3.pc

	$(INSTALL_DATA) -D -m 0644 $(PKG_BUILD_DIR)/eigen3.pc $(1)/usr/lib/pkgconfig/eigen3.pc
	
	$(INSTALL_DIR) $(1)/usr/include/eigen3
	$(CP) -a $(PKG_BUILD_DIR)/Eigen $(1)/usr/include/eigen3
	mkdir -p $(1)/usr/include/eigen3/unsupported
	$(CP) -a $(PKG_BUILD_DIR)/unsupported/Eigen $(1)/usr/include/eigen3/unsupported
endef

$(eval $(call BuildPackage,eigen))
