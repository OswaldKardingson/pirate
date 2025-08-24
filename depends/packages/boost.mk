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
  CXX_CANDIDATES="$($(package)_cxx)"; \
  case "$(host_os)" in \
    mingw64|mingw32) CXX_CANDIDATES="x86_64-w64-mingw32-g++ g++ $$CXX_CANDIDATES" ;; \
  esac; \
  CXX_BIN=""; \
  for c in $$CXX_CANDIDATES; do \
    if command -v "$$c" >/dev/null 2>&1; then CXX_BIN="$$c"; break; fi; \
  done; \
  if [ -z "$$CXX_BIN" ]; then CXX_BIN="$($(package)_cxx)"; fi; \
  if command -v "$$CXX_BIN" >/dev/null 2>&1; then \
    CXX_PATH="$$CXX_BIN"; \
  else \
    CXX_PATH="$$(which $$CXX_BIN)"; \
  fi; \
  AR_BIN="$($(package)_ar)"; RANLIB_BIN="$(host_RANLIB)"; STRIP_BIN="$(host_STRIP)"; WINDRES_BIN="$(host_WINDRES)"; \
  for v in AR_BIN RANLIB_BIN STRIP_BIN WINDRES_BIN; do \
    val="${!v}"; \
    if [ -n "$$val" ]; then \
      if command -v "$$val" >/dev/null 2>&1; then \
        eval ${v}_PATH="$$val"; \
      else \
        eval ${v}_PATH="$$(which $$val 2>/dev/null)"; \
      fi; \
    fi; \
  done; \
  if command -v cygpath >/dev/null 2>&1; then \
    CXX_PATH_WIN="$$(cygpath -w "$$CXX_PATH" 2>/dev/null || echo "$$CXX_PATH")"; \
    AR_PATH_WIN="$$(cygpath -w "$$AR_BIN_PATH" 2>/dev/null || echo "$$AR_BIN_PATH")"; \
    RANLIB_PATH_WIN="$$(cygpath -w "$$RANLIB_BIN_PATH" 2>/dev/null || echo "$$RANLIB_BIN_PATH")"; \
    STRIP_PATH_WIN="$$(cygpath -w "$$STRIP_BIN_PATH" 2>/dev/null || echo "$$STRIP_BIN_PATH")"; \
    WINDRES_PATH_WIN="$$(cygpath -w "$$WINDRES_BIN_PATH" 2>/dev/null || echo "$$WINDRES_BIN_PATH")"; \
  else \
    CXX_PATH_WIN="$$CXX_PATH"; \
    AR_PATH_WIN="$$AR_BIN_PATH"; \
    RANLIB_PATH_WIN="$$RANLIB_BIN_PATH"; \
    STRIP_PATH_WIN="$$STRIP_BIN_PATH"; \
    WINDRES_PATH_WIN="$$WINDRES_BIN_PATH"; \
  fi; \
  echo "using $($(package)_toolset_$(host_os)) : : $$CXX_PATH_WIN : <cflags>\"$($(package)_cflags)\" <cxxflags>\"$($(package)_cxxflags)\" <compileflags>\"$($(package)_cppflags)\" <linkflags>\"$($(package)_ldflags)\" <archiver>\"$$AR_PATH_WIN\" <striper>\"$$STRIP_PATH_WIN\"  <ranlib>\"$$RANLIB_PATH_WIN\" <rc>\"$$WINDRES_PATH_WIN\" : ;" > user-config.jam
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
