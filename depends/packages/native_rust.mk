package=native_rust
$(package)_version=1.78.0
$(package)_download_path=https://static.rust-lang.org/dist

# 1. Define all platform-specific file names and hashes first
$(package)_file_name_linux=rust-$($(package)_version)-x86_64-unknown-linux-gnu.tar.gz
$(package)_sha256_hash_linux=1307747915e8bd925f4d5396ab2ae3d8d9c7fad564afbc358c081683d0f22e87
$(package)_file_name_darwin=rust-$($(package)_version)-x86_64-apple-darwin.tar.gz
$(package)_sha256_hash_darwin=6c91ed3bd90253961fcb4a2991b8b22e042e2aaa9aba9f389f1e17008171d898
$(package)_file_name_freebsd=rust-$($(package)_version)-x86_64-unknown-freebsd.tar.gz
$(package)_sha256_hash_freebsd=b9cc84c60deb8da08a6c876426f8721758f4c7e7c553b4554385752ad37c63df
$(package)_file_name_aarch64_linux=rust-$($(package)_version)-aarch64-unknown-linux-gnu.tar.gz
$(package)_sha256_hash_aarch64_linux=131eda738cd977fff2c912e5838e8e9b9c260ecddc1247c0fe5473bf09c594af
$(package)_file_name_windows=rust-$($(package)_version)-x86_64-pc-windows-gnu.tar.gz
$(package)_sha256_hash_windows=3c6b4f2e48a4ec4a4ff204a5611cafd9167eacfeb7f4b162e0d429c9b42327b4

# 2. Determine _file_name_to_use and _sha256_hash_to_use based on (stripped) build_os
_tmp_build_os := $(strip $(build_os))
ifeq ($(_tmp_build_os),mingw32)
  _file_name_to_use := $($(package)_file_name_windows)
  _sha256_hash_to_use := $($(package)_sha256_hash_windows)
else ifeq ($(_tmp_build_os),linux)
  ifeq ($(strip $(build_arch)),aarch64)
    _file_name_to_use := $($(package)_file_name_aarch64_linux)
    _sha256_hash_to_use := $($(package)_sha256_hash_aarch64_linux)
  else
    _file_name_to_use := $($(package)_file_name_linux)
    _sha256_hash_to_use := $($(package)_sha256_hash_linux)
  endif
else ifeq ($(_tmp_build_os),darwin)
  _file_name_to_use := $($(package)_file_name_darwin)
  _sha256_hash_to_use := $($(package)_sha256_hash_darwin)
else ifeq ($(_tmp_build_os),freebsd)
  _file_name_to_use := $($(package)_file_name_freebsd)
  _sha256_hash_to_use := $($(package)_sha256_hash_freebsd)
else
  # Fallback, with a warning or error if possible, for now default to linux x86
  _file_name_to_use := $($(package)_file_name_linux)
  _sha256_hash_to_use := $($(package)_sha256_hash_linux)
endif

# 3. Assign to the main package variables, stripping results
$(package)_file_name = $(strip $(_file_name_to_use))
$(package)_download_file = $(strip $(_file_name_to_use))
$(package)_sha256_hash = $(strip $(_sha256_hash_to_use))

# --- Original Rust target mappings and std sha256 hashes (keep these as they are) ---
$(package)_rust_target_x86_64-pc-linux-gnu=x86_64-unknown-linux-gnu
$(package)_rust_target_x86_64-w64-mingw32=x86_64-pc-windows-gnu

$(package)_rust_std_sha256_hash_aarch64-unknown-linux-gnu=8f42b40c0a0658ee75ce758652c9821fac7db3fbd8d20f7fb2483ec2c57ee0ac
$(package)_rust_std_sha256_hash_x86_64-apple-darwin=e44d71250dc5a238da0dc4784dad59d562862653adecd31ea52e0920b85c6a7c
$(package)_rust_std_sha256_hash_x86_64-pc-windows-gnu=09ded4a4c27c16aff9c9911640b1bdf6e1172237ce540ed4dc3e166e9438f0d7
$(package)_rust_std_sha256_hash_x86_64-unknown-freebsd=eed4b3f3358a8887b0f6a62e021469878a8990af9b94c2fe87d3c1b0220913bb
$(package)_rust_std_sha256_hash_x86_64-unknown-linux-gnu=5e7738090baf6dc12c3ed62fb02cf51f80af2403f6df85feae0ebf157e2d8d35
# --- End of original Rust target mappings ---

define rust_target
$(if $($(1)_rust_target_$(2)),$($(1)_rust_target_$(2)),$(if $(findstring darwin,$(3)),x86_64-apple-darwin,$(if $(findstring freebsd,$(3)),x86_64-unknown-freebsd,$(2))))
endef

define $(package)_set_vars
$(package)_stage_opts=--disable-ldconfig
$(package)_stage_build_opts=--without=rust-docs-json-preview,rust-docs
endef

# --- Conditional logic for cross-compilation vs native ---
ifneq ($(canonical_host),$(build))
  $(package)_rust_target=$(call rust_target,$(package),$(canonical_host),$(host_os))
  $(package)_exact_file_name=rust-std-$($(package)_version)-$($(package)_rust_target).tar.gz
  $(package)_exact_sha256_hash=$($(package)_rust_std_sha256_hash_$($(package)_rust_target))
  $(package)_build_subdir=buildos
  $(package)_extra_sources = $($(package)_file_name)

  define $(package)_fetch_cmds
    $(call fetch_file,$(package),$($(package)_download_path),$($(package)_exact_file_name),$($(package)_exact_file_name),$($(package)_exact_sha256_hash)) && \
    $(call fetch_file,$(package),$($(package)_download_path),$($(package)_extra_sources),$($(package)_extra_sources),$($(package)_sha256_hash))
  endef

  define $(package)_extract_cmds
    mkdir -p $($(package)_extract_dir) && \
    cd $($(package)_extract_dir) && \
    mkdir -p $(canonical_host) buildos && \
    echo "$($(package)_exact_sha256_hash)  $($(package)_source_dir)/$($(package)_exact_file_name)" > .$($(package)_exact_file_name).hash && \
    echo "$($(package)_sha256_hash)  $($(package)_source_dir)/$($(package)_extra_sources)" > .$($(package)_extra_sources).hash && \
    $(build_SHA256SUM) -c .$($(package)_exact_file_name).hash && \
    $(build_SHA256SUM) -c .$($(package)_extra_sources).hash && \
    tar --strip-components=1 -xf $($(package)_source_dir)/$($(package)_exact_file_name) -C $(canonical_host) && \
    tar --strip-components=1 -xf $($(package)_source_dir)/$($(package)_extra_sources) -C buildos
  endef

  define $(package)_stage_cmds
    bash ./install.sh --destdir=$($(package)_staging_dir) --prefix=$(build_prefix) $($(package)_stage_opts) $($(package)_stage_build_opts) && \
    ../$(canonical_host)/install.sh --destdir=$($(package)_staging_dir) --prefix=$(build_prefix) $($(package)_stage_opts)
  endef
else # Native build
  # For native builds, _extra_sources isn't strictly needed by fetch_cmds the same way,
  # as only one rust toolchain (primary) is downloaded by default fetch_cmds in funcs.mk
  # $(package)_extra_sources is not used by default $(package)_extract_cmds from funcs.mk
  define $(package)_stage_cmds # Simpler for native
    bash ./install.sh --destdir=$($(package)_staging_dir) --prefix=$(build_prefix) $($(package)_stage_opts) $($(package)_stage_build_opts)
  endef
endif
