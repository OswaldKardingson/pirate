package=boost
$(package)_version=1_83_0
$(package)_download_path=https://archives.boost.io/release/$(subst _,.,$($(package)_version))/source/
$(package)_file_name=boost_$($(package)_version).tar.bz2
$(package)_sha256_hash=6478edfe2f3305127cffe8caf73ea0176c53769f4bf1585be237eb30798c3b8e
$(package)_dependencies=native_b2
$(package)_patches=6753-signals2-function-fix.patch


define $(package)_set_vars
$(package)_config_opts_release=variant=release
$(package)_config_opts_debug=variant=debug
$(package)_config_opts=--layout=system --user-config=user-config.jam
$(package)_config_opts+=threading=multi link=static -sNO_COMPRESSION=1
$(package)_config_opts_linux=target-os=linux threadapi=pthread runtime-link=shared
$(package)_config_opts_freebsd=cxxflags=-fPIC
$(package)_config_opts_darwin=target-os=darwin runtime-link=shared
$(package)_config_opts_mingw32=target-os=windows binary-format=pe threadapi=win32 runtime-link=static
$(package)_config_opts_mingw64=target-os=windows binary-format=pe threadapi=win32 runtime-link=static
$(package)_config_opts_x86_64=architecture=x86 address-model=64
$(package)_config_opts_i686=architecture=x86 address-model=32
$(package)_config_opts_aarch64=address-model=64
$(package)_config_opts_armv7a=address-model=32
$(package)_toolset_$(host_os)=gcc
$(package)_config_libraries=chrono,filesystem,program_options,system,thread,test
$(package)_cxxflags+=-std=c++17 -fvisibility=hidden
$(package)_cxxflags_linux=-fPIC
$(package)_cxxflags_freebsd=-fPIC


endef

# On MSYS2, b2 sometimes fails to resolve the triplet-prefixed compiler
# when only the bare name is provided. We'll detect the absolute path in preprocess step.

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/6753-signals2-function-fix.patch && \
  if [ "$(host_os)" = "mingw64" ] || [ "$(host_os)" = "mingw32" ]; then \
    CXX_CANDIDATES="$($(package)_cxx) x86_64-w64-mingw32-g++ g++"; \
    CXX_BIN=""; \
    for c in $$CXX_CANDIDATES; do \
      if command -v "$$c" >/dev/null 2>&1; then CXX_BIN="$$c"; break; fi; \
    done; \
    if [ -z "$$CXX_BIN" ]; then CXX_BIN="$($(package)_cxx)"; fi; \
    CXX_PATH="$$CXX_BIN"; \
    AR_PATH="$($(package)_ar)"; RANLIB_PATH="$(host_RANLIB)"; STRIP_PATH="$(host_STRIP)"; WINDRES_PATH="$(host_WINDRES)"; \
    if command -v cygpath >/dev/null 2>&1; then \
      CXX_PATH="$$(cygpath -w "$$CXX_PATH" 2>/dev/null || echo "$$CXX_PATH")"; \
      if [ -n "$$AR_PATH" ]; then AR_PATH="$$(cygpath -w "$$AR_PATH" 2>/dev/null || echo "$$AR_PATH")"; fi; \
      if [ -n "$$RANLIB_PATH" ]; then RANLIB_PATH="$$(cygpath -w "$$RANLIB_PATH" 2>/dev/null || echo "$$RANLIB_PATH")"; fi; \
      if [ -n "$$STRIP_PATH" ]; then STRIP_PATH="$$(cygpath -w "$$STRIP_PATH" 2>/dev/null || echo "$$STRIP_PATH")"; fi; \
      if [ -n "$$WINDRES_PATH" ]; then WINDRES_PATH="$$(cygpath -w "$$WINDRES_PATH" 2>/dev/null || echo "$$WINDRES_PATH")"; fi; \
    fi; \
    echo "using $($(package)_toolset_$(host_os)) : : $$CXX_PATH : <cflags>\"$($(package)_cflags)\" <cxxflags>\"$($(package)_cxxflags)\" <compileflags>\"$($(package)_cppflags)\" <linkflags>\"$($(package)_ldflags)\" <archiver>\"$$AR_PATH\" <striper>\"$$STRIP_PATH\"  <ranlib>\"$$RANLIB_PATH\" <rc>\"$$WINDRES_PATH\" : ;" > user-config.jam; \
  else \
    echo "using $($(package)_toolset_$(host_os)) : : $($(package)_cxx) : <cflags>\"$($(package)_cflags)\" <cxxflags>\"$($(package)_cxxflags)\" <compileflags>\"$($(package)_cppflags)\" <linkflags>\"$($(package)_ldflags)\" <archiver>\"$($(package)_ar)\" <striper>\"$(host_STRIP)\"  <ranlib>\"$(host_RANLIB)\" <rc>\"$(host_WINDRES)\" : ;" > user-config.jam; \
  fi
endef

define $(package)_config_cmds
  ./bootstrap.sh --without-icu --with-libraries=$(if $(filter $(host_os),mingw64 mingw32),chrono,filesystem,program_options,system,thread,$($(package)_config_libraries)) --with-toolset=$($(package)_toolset_$(host_os)) --with-bjam=b2 --libdir=lib
endef

define $(package)_build_cmds
  b2 -d2 -j2 -d1 --prefix=$($(package)_staging_prefix_dir) $($(package)_config_opts) toolset=$($(package)_toolset_$(host_os)) stage
endef

define $(package)_stage_cmds
  b2 -d0 -j4 --prefix=$($(package)_staging_prefix_dir) $($(package)_config_opts) toolset=$($(package)_toolset_$(host_os)) install
endef
