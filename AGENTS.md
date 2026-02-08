# Avogadro Project

For Avogadro, code needs to be **correct** particularly for science-related topics. The force fields, the molecular dynamics, molecular surfaces, orbitals, etc. needs substantial human intervention and review. We suggest that agents be used primarily for writing small snippets and boilerplate, with full, careful human analysis particularly for chemical and mathematical components.

Avogadro is an open source C++ desktop chemistry app, focusing on building, editing and visualizing molecules and materials. This includes running simple simulations, geometry optimizations, analysis and OpenGL visualization. The avogadrolibs repository focuses on the key library components including `avogadro/calc` for calculating atomic charges and energies, `avogadro/core` for fundamental non-UI classes, `avogadro/io` for core file format IO, `avogadro/qtgui` for core Qt UI classes, `avogadro/qtplugins` for isolated plugin classes as menu actions, tools, and rendering display plugins, `avogadro/quantumio` for reading quantum chemical formats, and `avogadro/rendering` for OpenGL rendering code including GLSL shaders.

## 🧠 Context

- **Project Type**: Cross-Platform Desktop App
- **Purpose**: Scientific Visualization / Molecular Modeling / Computational Chemistry
- **Language**: C++ 17 and GLSL
- **Framework / Libraries**: STL / Qt / CMake / GoogleTest / OpenGL / Eigen
- **Architecture**: Modular / Layered / RAII / OOP / Component-Based

## 🔧 General Guidelines

- Use modern C++ (C++17 where supported).
- Add unit tests to `tests/` for new features.
- Add regression tests for bug fixes.
- Favor smart pointers (`std::unique_ptr`, `std::shared_ptr`) over raw pointers.
- Use `const`, `constexpr`, and `noexcept` to express intent.
- Try to keep headers clean -- generally avoid logic in header files.
- Use `clang-format` for consistent formatting (see `.clang-format` at the repo root).
- Favor readability, modularity, and safety. Code should never crash or leak memory.
- Give information about any CMake Policies that might affect CMake variables that are suggested or mentioned.
- This project needs to be cross-platform for Windows, macOS, Linux, and BSD and cross-compiler for MSVC, Clang, and GCC.
  - Minimum CMake version is 3.24, so policies in that range may apply.


## 📁 File Structure

Use this structure as a guide when creating or updating files:

```text
avogadro/
  calc/
  command/
  core/
  io/
  molequeue/
  qtgui/
  qtopengl/
  qtplugins/
  quantumio/
  rendering/
tests/
  calc/
  core/
  io/
  qtgui/
  rendering/
thirdparty/
```

## 🧶 Patterns

### ✅ Patterns to Follow

- Classes in `core` should have no external dependencies (Eigen is okay). Any classes requiring Qt should be in `qtgui` and any code using OpenGL should be in `rendering`.
- File format classes are handled in `io` which only depends on `core`. Quantum chemical program formats are generally handled in `quantumio`
- Calculations such as charge models and force fields (e.g., Lennard-Jones and UFF) are found in `calc`. These should leverage vector methods in Eigen where possible.
- Encapsulate with classes and clean header/implementation separation.
- Favor the Rule of 5 or Rule of 0 when managing custom types.
- Use interfaces (`abstract class`) for testability and polymorphism.
- Prefer `enum class` over unscoped enums.
- Use CMake targets and `target_include_directories` for modular build config.

### 🚫 Patterns to Avoid

- Avoid macros for constants: prefer `constexpr` or `inline` `const`.
- Avoid implementation logic in header files unless using templates.
- Avoid global variables unless necessary and wrapped in a namespace or singleton.
- Don’t overuse inheritance; prefer composition.
- Avoid manual memory management unless absolutely required.

## 🧪 Testing Guidelines

- Use `GoogleTest` for unit testing.
- Test constructors, copy/move semantics, and edge cases.
- Write tests for all public APIs.
- Isolate dependencies using mock interfaces or adapters.
- Test core logic in isolation from I/O or rendering subsystems.
- Use `CMake` to register and run tests via `ctest`.

## 🛠️ Build & Tooling

- In most cases, you wish to build through the `openchemistry` superbuild. For example, see our [build instructions](https://two.avogadro.cc/develop/build.html)
- Use a separate directory for `build`
- Configure: `cmake -S . -B build`
- Build: `cmake --build build`
- Test: `ctest --test-dir build`

## 🧩 Example Prompts

- `Create a C++ class for a thread-safe queue using std::mutex and std::condition_variable.`
- `Implement an abstract class Drawable with a draw() method and two subclasses.`
- `Write a GoogleTest unit test for the Molecule::centerOfGeometry method.`
- `Implement a C++ string buffer for uncompressing streams using libarchive.`
- `Please help modernize this OpenGL code to support the 4.0 core profile`

## 🔁 Iteration & Review

- Always review generated code for security, memory safety and correctness.
- Consider edge cases, for example colinear angles, molecules with no atoms, etc.
- Use comments to explain complex logic and guide suggestions.
- Refactor output to match the project's code conventions.
- Run `clang-tidy`, `cppcheck`, and sanitizers on generated code for static analysis.

## 📚 References

- [C++ Core Guidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines)
- [Modern C++ Features (C++17/20)](https://github.com/AnthonyCalandra/modern-cpp-features)
- [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html)
- [CMake Documentation](https://cmake.org/documentation/)
- [GoogleTest Documentation](https://github.com/google/googletest)
- [Clang-Tidy Checks](https://clang.llvm.org/extra/clang-tidy/)
- [CppReference STL Docs](https://en.cppreference.com/w/cpp)
