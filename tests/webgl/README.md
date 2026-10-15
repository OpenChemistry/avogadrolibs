# WebGL input regression test

This standalone Emscripten test consumes an installed AvogadroLibs package and
runs under Node.js. It checks that BGR/BGRA textures and both double-attribute
APIs fail before touching GL state. It needs no browser or GL context.

Configure with the same Qt/Emscripten toolchain, SDK cache and dependency roots
as the library build. For example (replace the paths):

```sh
cmake -S tests/webgl -B build-webgl-tests \
  -DCMAKE_TOOLCHAIN_FILE=/path/to/Qt/wasm_multithread/lib/cmake/Qt6/qt.toolchain.cmake \
  -DQT_CHAINLOAD_TOOLCHAIN_FILE=/path/to/emscripten/cmake/Modules/Platform/Emscripten.cmake \
  -DCMAKE_FIND_ROOT_PATH=/path/to/installed/dependencies \
  -DAvogadroLibs_DIR=/path/to/install/lib/cmake/avogadrolibs \
  -DCMAKE_CROSSCOMPILING_EMULATOR=/path/to/node
cmake --build build-webgl-tests
ctest --test-dir build-webgl-tests --output-on-failure
```

This test does not validate browser rendering. The native `Rendering-GLRenderer`
test exercises the solid pipeline using optional surfaceless EGL on Linux,
including ambient occlusion. It skips if the required graphics context is
unavailable. Browser testing is still needed for WebGL extension availability
and the embedded Qt window's input handling.
