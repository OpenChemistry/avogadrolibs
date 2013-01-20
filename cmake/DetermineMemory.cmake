# Find the best mutex class available on the current platform. This defaults to
# using the C++11 mutex if available, and falling back to the Boost mutex.
function(determine_memory_ptrs typedefs includes)

  set(RESULT 0)
  set(MEMORY_TYPES_FOUND FALSE)

  # Look for the C++11 version.
  if(NOT MEMORY_TYPES_FOUND)
    file(WRITE "${PROJECT_BINARY_DIR}/CMakeTmp/memory.cpp"
"#include <memory>
int main(int, char * [])
{
  std::unique_ptr<float> uniquePtr;
  std::shared_ptr<float> sharedPtr;
  std::weak_ptr<float> weakPtr;
  return 0;
}
")
    try_compile(MEMORY_TYPES_FOUND
      ${PROJECT_BINARY_DIR}/CMakeTmp
      "${PROJECT_BINARY_DIR}/CMakeTmp/memory.cpp"
      COMPILE_DEFINITIONS ${CPP11_COMPILER_FLAGS})
    if(MEMORY_TYPES_FOUND)
      set(RESULT "
#define AVO_UNIQUE_PTR std::unique_ptr

using std::shared_ptr;
using std::weak_ptr;
")
      set(INCLUDE_RESULT "#include <memory>")
    endif()
  endif()

  # Fall back to Boost.
  if(NOT ${MUTEX_TYPE_FOUND} OR FORCE_ANSI_CPP)
    set(RESULT "
#define AVO_UNIQUE_PTR boost::scoped_ptr

using boost::shared_ptr;
using boost::weak_ptr;
")
    set(INCLUDE_RESULT "#include <boost/scoped_ptr.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/weak_ptr.hpp>")
    set(MEMORY_PTRS_BOOST_REQUIRED TRUE PARENT_SCOPE)
  endif()

  set(${typedefs} ${RESULT} PARENT_SCOPE)
  set(${includes} ${INCLUDE_RESULT} PARENT_SCOPE)

endfunction()
