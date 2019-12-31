include $(TOPDIR)/rules.mk

PKG_NAME:=fft2d
PKG_RELEASE:=1

PKG_SOURCE = $(PKG_NAME).tgz
PKG_SOURCE_URL:=https://storage.googleapis.com/mirror.tensorflow.org/www.kurims.kyoto-u.ac.jp/~ooura
PKG_HASH:=ada7e99087c4ed477bfdf11413f2ba8db8a840ba9bbf8ac94f4f3972e2a7cec9

PKG_INSTALL:=1
PKG_MAINTAINER:=Exein <info@exein.io>


include $(INCLUDE_DIR)/package.mk

define Package/fft2d
	SECTION:=libs
	CATEGORY:=Tensorflow
	SUBMENU:=Libraries
	TITLE:=General Purpose FFT (Fast Fourier/Cosine/Sine Transform) Package.
endef

define Build/Compile
	cd $(PKG_BUILD_DIR); \
	$(TARGET_CC) -shared -o $(PKG_BUILD_DIR)/liballoc.so -fPIC alloc.c; \
	$(TARGET_CC) -shared -o $(PKG_BUILD_DIR)/libfft4f2d.so -fPIC fft4f2d.c; \
	$(TARGET_CC) -shared -o $(PKG_BUILD_DIR)/libfftsg.so -fPIC fftsg.c; \
	$(TARGET_CC) -shared -o $(PKG_BUILD_DIR)/libfftsg2d.so -fPIC fftsg2d.c; \
	$(TARGET_CC) -shared -o $(PKG_BUILD_DIR)/libfftsg3d.so -fPIC fftsg3d.c; \
	$(TARGET_CC) -shared -o $(PKG_BUILD_DIR)/libshrtdct.so -fPIC shrtdct.c
endef


define Package/fft2d/install
	$(INSTALL_DIR) $(1)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/lib*.so $(1)/usr/lib
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/lib*.so $(1)/usr/lib

	$(INSTALL_DIR) $(1)/usr/include/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/*.h $(1)/usr/include
endef


$(eval $(call BuildPackage,fft2d))
