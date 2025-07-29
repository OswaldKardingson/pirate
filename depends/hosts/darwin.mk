OSX_MIN_VERSION=11.0
OSX_SDK_VERSION=11.0
OSX_SDK=$(SDK_PATH)/MacOSX$(OSX_SDK_VERSION).sdk
LD64_VERSION=711

# Flag explanations:
#
#     -mlinker-version
#
#         Ensures that modern linker features are enabled. See here for more
#         details: https://github.com/bitcoin/bitcoin/pull/19407.
#
#     -B$(build_prefix)/bin
#
#         Explicitly point to our binaries (e.g. cctools) so that they are
#         ensured to be found and preferred over other possibilities.
#
#     -nostdinc++ -isystem $(OSX_SDK)/usr/include/c++/v1
#
#         Forces clang to use the libc++ headers from our SDK and completely
#         forget about the libc++ headers from the standard directories
#
#         TODO: Once we start requiring a clang version that has the
#         -stdlib++-isystem<directory> flag first introduced here:
#         https://reviews.llvm.org/D64089, we should use that instead. Read the
#         differential summary there for more details.
#

# Force universal cross-compile to x86_64 so that C/C++ objects match the Rust
# standard libraries shipped in the depends toolchain (which are always built
# for x86_64-apple-darwin). On Apple Silicon runners `$(host)` is `arm-apple-darwin*`,
# leading to architecture mismatches at link-time. We instead hard-code the
# target triple here; this is safe because the produced binaries are intended
# for distribution to Intel macOS users.

# Detect the actual architecture we're building for and set appropriate Rust target
ifeq ($(host),x86_64-apple-darwin)
    darwin_cross_target = x86_64-apple-darwin
    RUST_TARGET = x86_64-apple-darwin
else ifeq ($(host),aarch64-apple-darwin)
    darwin_cross_target = aarch64-apple-darwin
    RUST_TARGET = aarch64-apple-darwin
else
    # Default fallback for compatibility
    darwin_cross_target = x86_64-apple-darwin
    RUST_TARGET = x86_64-apple-darwin
endif

darwin_CC=clang -target $(darwin_cross_target) -mmacosx-version-min=$(OSX_MIN_VERSION) --sysroot $(OSX_SDK) -mlinker-version=$(LD64_VERSION) -B$(build_prefix)/bin
darwin_CXX=clang++ -target $(darwin_cross_target) -mmacosx-version-min=$(OSX_MIN_VERSION) --sysroot $(OSX_SDK) -stdlib=libc++ -mlinker-version=$(LD64_VERSION) -B$(build_prefix)/bin -nostdinc++ -isystem $(OSX_SDK)/usr/include/c++/v1

darwin_CFLAGS=-pipe
darwin_CXXFLAGS=$(darwin_CFLAGS)

darwin_release_CFLAGS=-O2
darwin_release_CXXFLAGS=$(darwin_release_CFLAGS)

darwin_debug_CFLAGS=-O1
darwin_debug_CXXFLAGS=$(darwin_debug_CFLAGS)

darwin_native_binutils=native_cctools
ifeq ($(strip $(FORCE_USE_SYSTEM_CLANG)),)
darwin_native_toolchain=native_cctools
else
darwin_native_toolchain=
endif

darwin_cmake_system=Darwin
