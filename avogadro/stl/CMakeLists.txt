# Test for some C++11 language features, if not present find the Boost libraries
# FindBoost(...) requires this to be set on Windows.
if(NOT BUILD_SHARED_LIBS OR WIN32)
  set(Boost_USE_STATIC_LIBS ON)
endif()

# Mutex
include(DetermineMutex)
determine_mutex(MUTEX_TYPE MUTEX_TYPE_HEADER)
# Currently not installed, for use in Avogadro internal libraries only.
configure_file("${PROJECT_SOURCE_DIR}/cmake/mutex.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/mutex_p.h" @ONLY)
if(MUTEX_TYPE_BOOST_REQUIRED)
  message(STATUS
    "Using Boost to replace C++11 mutex that is not available.")
  find_package(Boost COMPONENTS thread system chrono REQUIRED)
  find_package(Threads)
  set(AvogadroLibs_NEEDS_BOOST TRUE CACHE INTERNAL
    "AvogadroLibs requires some Boost components to replace C++11 features")
  set(AvogadroLibs_MUTEX_BOOST_LIBRARIES
    "${Boost_LIBRARIES};${CMAKE_THREAD_LIBS_INIT}" CACHE INTERNAL
    "The Boost libraries we require for Mutex support")
  set(AvogadroLibs_MUTEX_INCLUDE_DIRS "${Boost_INCLUDE_DIRS}" CACHE INTERNAL
    "The Boost libraries we require for Mutex support")
endif()

# Smart pointer classes.
include(DetermineMemory)
determine_memory_ptrs(MEMORY_TYPEDEFS MEMORY_TYPE_INCLUDES)
# Currently not installed, for use in Avogadro internal libraries only.
configure_file("${PROJECT_SOURCE_DIR}/cmake/memory.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/memory_p.h" @ONLY)
if(MEMORY_PTRS_BOOST_REQUIRED)
  message(STATUS
    "Using Boost to replace C++11 smart pointers that are not available.")
  find_package(Boost REQUIRED)
  set(AvogadroLibs_NEEDS_BOOST TRUE CACHE INTERNAL
    "AvogadroLibs requires some Boost components to replace C++11 features")
  set(AvogadroLibs_MEMORY_INCLUDE_DIRS "${Boost_INCLUDE_DIRS}" CACHE INTERNAL
    "The Boost libraries we require for Mutex support")
endif()

if(AvogadroLibs_NEEDS_BOOST)
  if(WIN32)
    set(AvogadroLibs_BOOST_DEFINITIONS "-DBOOST_ALL_NO_LIB" CACHE INTERNAL
      "Any additional compiler definitions required in order to use Boost")
  else()
    set(AvogadroLibs_BOOST_DEFINITIONS "" CACHE INTERNAL
      "Any additional compiler definitions required in order to use Boost")
  endif()
endif()
