package=native_protobuf
$(package)_version=2.6.1
$(package)_download_path=https://github.com/google/protobuf/releases/download/v$($(package)_version)
$(package)_file_name=protobuf-$($(package)_version).tar.bz2
$(package)_sha256_hash=ee445612d544d885ae240ffbcbf9267faa9f593b7b101f21d58beceb92661910

define $(package)_set_vars
$(package)_config_opts=--disable-shared --without-zlib
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  if test "$(build_os)" = "mingw32" -o "$(build_os)" = "mingw64"; then \
    $(MAKE) -C src all; \
  else \
    $(MAKE) -C src protoc; \
  fi
endef

define $(package)_stage_cmds
  if test "$(build_os)" = "mingw32" -o "$(build_os)" = "mingw64"; then \
    $(MAKE) DESTDIR=$($(package)_staging_dir) install-strip; \
  else \
    $(MAKE) -C src DESTDIR=$($(package)_staging_dir) install-strip; \
  fi
endef

define $(package)_postprocess_cmds
  rm -rf lib include
endef
