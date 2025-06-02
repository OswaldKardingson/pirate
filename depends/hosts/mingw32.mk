mingw32_CC=x86_64-w64-mingw32-gcc-posix
mingw32_CXX=x86_64-w64-mingw32-g++-posix
mingw32_CFLAGS=-pipe -std=c17
mingw32_CXXFLAGS=-pipe -std=c++17

BASE64_TOOL = base64 --decode # Define BASE64_TOOL for MinGW

mingw32_release_CFLAGS=-g -O2
mingw32_release_CXXFLAGS=$(mingw32_CXXFLAGS) $(mingw32_release_CFLAGS)

mingw32_debug_CFLAGS=-O1
mingw32_debug_CXXFLAGS=$(mingw32_debug_CFLAGS)

mingw32_debug_CFLAGS=-g -O0
mingw32_debug_CPPFLAGS=-D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC
mingw32_debug_CXXFLAGS=$(mingw32_CXXFLAGS) $(mingw32_debug_CFLAGS)
