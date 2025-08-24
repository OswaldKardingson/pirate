mingw64_CC=x86_64-w64-mingw32-gcc
mingw64_CXX=x86_64-w64-mingw32-g++
mingw64_CFLAGS=-pipe -std=c17
mingw64_CXXFLAGS=-pipe -std=c++17

# Add binutils tool names to match MSYS2 triplet ("mingw32" for 64-bit toolchain)
mingw64_AR=x86_64-w64-mingw32-ar
mingw64_RANLIB=x86_64-w64-mingw32-ranlib
mingw64_STRIP=x86_64-w64-mingw32-strip
mingw64_NM=x86_64-w64-mingw32-nm
mingw64_WINDRES=x86_64-w64-mingw32-windres

BASE64_TOOL = base64 --decode # Define BASE64_TOOL for MinGW

mingw64_release_CFLAGS=-g -O2
mingw64_release_CXXFLAGS=$(mingw64_CXXFLAGS) $(mingw64_release_CFLAGS)

mingw64_debug_CFLAGS=-O1
mingw64_debug_CXXFLAGS=$(mingw64_debug_CFLAGS)

mingw64_debug_CFLAGS=-g -O0
mingw64_debug_CPPFLAGS=-D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC
mingw64_debug_CXXFLAGS=$(mingw64_CXXFLAGS) $(mingw64_debug_CFLAGS) 