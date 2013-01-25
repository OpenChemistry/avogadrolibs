# Find the best mutex class available on the current platform. This defaults to
# using the C++11 mutex if available, and falling back to the Boost mutex.
function(determine_mutex type incType)

  set(RESULT 0)
  set(MUTEX_TYPE_FOUND FALSE)

  # Look for the C++11 version.
  if(NOT MUTEX_TYPE_FOUND)
    file(WRITE "${PROJECT_BINARY_DIR}/CMakeTmp/mutex.cpp"
"#include <mutex>
int main(int, char * [])
{
  std::mutex mutex;
  return 0;
}
")
    try_compile(MUTEX_TYPE_FOUND
      ${PROJECT_BINARY_DIR}/CMakeTmp
      "${PROJECT_BINARY_DIR}/CMakeTmp/mutex.cpp"
      COMPILE_DEFINITIONS ${CXX11_FLAGS})
    if(MUTEX_TYPE_FOUND)
      set(RESULT "std::mutex")
      set(INCLUDE_RESULT "mutex")
    endif()
  endif()

  # Fall back to Boost.
  if(NOT MUTEX_TYPE_FOUND OR FORCE_ANSI_CPP)
    set(RESULT "boost::mutex")
    set(INCLUDE_RESULT "boost/thread/mutex.hpp")
    set(${type}_BOOST_REQUIRED TRUE PARENT_SCOPE)
  endif()

  set(${type} ${RESULT} PARENT_SCOPE)
  set(${incType} ${INCLUDE_RESULT} PARENT_SCOPE)

endfunction()
