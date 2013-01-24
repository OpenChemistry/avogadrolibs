# Determine if any special flags are needed for C++11 support to be enabled.
set(CPP11_COMPILER_FLAGS "")

if(CMAKE_COMPILER_IS_GNUCXX)

  include(CheckCXXCompilerFlag)

  # Addtional warnings for GCC
  set(CMAKE_CXX_FLAGS_WARN "-Wnon-virtual-dtor -Wno-long-long -Wcast-align -Wchar-subscripts -Wall -Wpointer-arith -Wformat-security -Woverloaded-virtual -fno-check-new -fno-common")

  # This flag is useful as not returning from a non-void function is an error
  # with MSVC, but it is not supported on all GCC compiler versions
  check_cxx_compiler_flag("-Werror=return-type" HAVE_GCC_ERROR_RETURN_TYPE)
  if(HAVE_GCC_ERROR_RETURN_TYPE)
    set(CMAKE_CXX_FLAGS_ERROR "-Werror=return-type")
  endif()
  if(FORCE_ANSI_CPP)
    set(HAVE_GCC_STD_CPP_03 FALSE)
    set(HAVE_GCC_STD_CPP_11 FALSE)
  else()
    check_cxx_compiler_flag("-std=c++03" HAVE_GCC_STD_CPP_03)
    check_cxx_compiler_flag("-std=c++11" HAVE_GCC_STD_CPP_11)
  endif()
  if(HAVE_GCC_STD_CPP_11)
    set(CMAKE_CXX_FLAGS_STD_CPP "-std=c++11 -pedantic -Wshadow -Wextra")
    set(CPP11_COMPILER_FLAGS "-std=c++11")
  elseif(HAVE_GCC_STD_CPP_03)
    set(CMAKE_CXX_FLAGS_STD_CPP "-std=c++03 -pedantic -Wshadow -Wextra")
  else()
    set(CMAKE_CXX_FLAGS_STD_CPP "-ansi")
  endif()

  # If we are compiling on Linux then set some extra linker flags too
  if(CMAKE_SYSTEM_NAME MATCHES Linux)
    set(CMAKE_SHARED_LINKER_FLAGS
      "-Wl,--fatal-warnings -Wl,--no-undefined -lc ${CMAKE_SHARED_LINKER_FLAGS}")
    set(CMAKE_MODULE_LINKER_FLAGS
      "-Wl,--fatal-warnings -Wl,--no-undefined -lc ${CMAKE_MODULE_LINKER_FLAGS}")
    set (CMAKE_EXE_LINKER_FLAGS
      "-Wl,--fatal-warnings -Wl,--no-undefined -lc ${CMAKE_EXE_LINKER_FLAGS}")
  endif()

  set(CMAKE_CXX_FLAGS_WARN "${CMAKE_CXX_FLAGS_WARN} ${CMAKE_CXX_FLAGS_STD_CPP}")
  # Set up the debug CXX_FLAGS for extra warnings
  set(CMAKE_CXX_FLAGS_RELWITHDEBINFO
    "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} ${CMAKE_CXX_FLAGS_WARN}")
  set(CMAKE_CXX_FLAGS_DEBUG
    "${CMAKE_CXX_FLAGS_DEBUG} ${CMAKE_CXX_FLAGS_WARN} ${CMAKE_CXX_FLAGS_ERROR}")
endif()
