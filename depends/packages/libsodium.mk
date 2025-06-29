package=libsodium
$(package)_version=1.0.18
$(package)_download_path=https://download.libsodium.org/libsodium/releases
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=6f504490b342a4f8a4c4a02fc9b866cbef8622d5df4e5452b46be121e46636c1
$(package)_dependencies=
$(package)_config_opts=

define $(package)_set_vars
  # Previously prevented automatic config script refresh; removed to support new macOS targets
  $(package)_build_env=
  # On macOS, ensure deployment target is set and updated config scripts are available
  ifeq ($(build_os),darwin)
  $(package)_build_env=MACOSX_DEPLOYMENT_TARGET="$(OSX_MIN_VERSION)"
  $(package)_cc=clang
  $(package)_cxx=clang++
  else
  $(package)_build_env=
  endif
endef

define $(package)_preprocess_cmds
  cd $($(package)_build_subdir); ./autogen.sh && \
  cp -f $(BASEDIR)/config.guess $(BASEDIR)/config.sub build-aux
endef

define $(package)_config_cmds
  $($(package)_autoconf) --enable-static --disable-shared
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
