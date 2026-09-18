if(CMAKE_COMPILER_IS_GNUCXX)

  include(CheckCXXCompilerFlag)

  # Additional warnings for GCC
  set(CMAKE_CXX_FLAGS_WARN "-Wnon-virtual-dtor -Wno-long-long -Wcast-align -Wchar-subscripts -Wall -Wpointer-arith -Wformat-security -Woverloaded-virtual -fno-check-new -fno-common")

  # This flag is useful as not returning from a non-void function is an error
  # with MSVC, but it is not supported on all GCC compiler versions
  check_cxx_compiler_flag("-Werror=return-type" HAVE_GCC_ERROR_RETURN_TYPE)
  if(HAVE_GCC_ERROR_RETURN_TYPE)
    set(CMAKE_CXX_FLAGS_ERROR "-Werror=return-type")
  endif()
  set(CMAKE_CXX_FLAGS_WARN "${CMAKE_CXX_FLAGS_WARN} -pedantic -Wshadow -Wextra")

  # If we are compiling on Linux then set some extra linker flags too
  if(CMAKE_SYSTEM_NAME MATCHES Linux)
    set(CMAKE_SHARED_LINKER_FLAGS
      "-Wl,--fatal-warnings -Wl,--no-undefined -lc ${CMAKE_SHARED_LINKER_FLAGS}")
    set(CMAKE_MODULE_LINKER_FLAGS
      "-Wl,--fatal-warnings -Wl,--no-undefined -lc ${CMAKE_MODULE_LINKER_FLAGS}")
    set (CMAKE_EXE_LINKER_FLAGS
      "-Wl,--fatal-warnings -Wl,--no-undefined -lc ${CMAKE_EXE_LINKER_FLAGS}")
  endif()

  # Set up the debug CXX_FLAGS for extra warnings
  set(CMAKE_CXX_FLAGS_RELWITHDEBINFO
    "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} ${CMAKE_CXX_FLAGS_WARN}")
  set(CMAKE_CXX_FLAGS_DEBUG
    "${CMAKE_CXX_FLAGS_DEBUG} ${CMAKE_CXX_FLAGS_WARN} ${CMAKE_CXX_FLAGS_ERROR}")
  set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")

  # Sanitizers
  set(CMAKE_CXX_FLAGS_TSAN "-fsanitize=thread -g -O1")
  set(CMAKE_CXX_FLAGS_ASAN "-fsanitize=address -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1")
  set(CMAKE_CXX_FLAGS_LSAN "-fsanitize=leak -fno-omit-frame-pointer -g -O1")
  set(CMAKE_CXX_FLAGS_MSAN "-fsanitize=memory -fno-optimize-sibling-calls -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -g -O2")
  set(CMAKE_CXX_FLAGS_UBSAN "-fsanitize=undefined")

elseif(MSVC)

  # AddressSanitizer, Visual Studio 2019 16.9 and newer. Windows produces more
  # crash reports than the other platforms and this is the only sanitizer the
  # toolchain offers: there is no ThreadSanitizer, MemorySanitizer or
  # LeakSanitizer for MSVC, so those stay on the Linux jobs.
  #
  # /O1 rather than a Debug-style /Od, because CMake's Debug configuration also
  # passes /RTC1 and ASan refuses to build alongside it. /Zi keeps the PDBs a
  # report needs to symbolicate.
  #
  # The container annotations are switched off deliberately. Qt, Open Babel and
  # everything else in the superbuild are not instrumented, and an annotated
  # std::vector or std::string crossing into uninstrumented code is reported as
  # a container overflow that is not one. Turn them back on if those ever get
  # instrumented too.
  set(CMAKE_CXX_FLAGS_ASAN
    "/fsanitize=address /Zi /O1 /D_DISABLE_VECTOR_ANNOTATION /D_DISABLE_STRING_ANNOTATION")
  set(CMAKE_C_FLAGS_ASAN "${CMAKE_CXX_FLAGS_ASAN}")

  # Incremental linking cannot be combined with ASan, and /DEBUG emits the PDB.
  set(CMAKE_EXE_LINKER_FLAGS_ASAN "/INCREMENTAL:NO /DEBUG")
  set(CMAKE_SHARED_LINKER_FLAGS_ASAN "/INCREMENTAL:NO /DEBUG")
  set(CMAKE_MODULE_LINKER_FLAGS_ASAN "/INCREMENTAL:NO /DEBUG")

endif()
