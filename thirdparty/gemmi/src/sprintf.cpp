// Copyright 2017 Global Phasing Ltd.

#include <gemmi/sprintf.hpp>
#include <stdarg.h>  // for va_list

#ifdef USE_STD_SNPRINTF  // useful for benchmarking and testing only
# include <cstdio>
# include <algorithm> // for min
#else
# define STB_SPRINTF_IMPLEMENTATION
# define STB_SPRINTF_STATIC
# define STB_SPRINTF_NOUNALIGNED 1
// Making functions from stb_sprintf static may trigger warnings.
# if defined(__GNUC__)
#  pragma GCC diagnostic ignored "-Wunused-function"
# endif
# if defined(__clang__)
#  pragma clang diagnostic ignored "-Wunused-function"
# endif

// To use system stb_sprintf.h (not recommended, but some Linux distros
// don't like bundled libraries) define GEMMI_USE_SYSTEM_STB or remove
// third_party/stb_sprintf.h.
# if defined(__has_include)
#  if !__has_include("../third_party/stb_sprintf.h")
#   define GEMMI_USE_SYSTEM_STB 1
#  endif
# endif
# ifdef GEMMI_USE_SYSTEM_STB
#  pragma message("Using system stb_sprintf.h, not the bundled one. It may not work.")
#  include <stb/stb_sprintf.h>
# else
#  include "../third_party/stb_sprintf.h"
# endif
#endif  // USE_STD_SNPRINTF

namespace gemmi {

// We copy functions from sprintf.h only to have them declared with GEMMI_DLL.
int sprintf_z(char *buf, char const *fmt, ...) {
  int result;
  va_list va;
  va_start(va, fmt);
#ifdef USE_STD_SNPRINTF
  result = std::vsprintf(buf, fmt, va);
#else
  result = STB_SPRINTF_DECORATE(vsprintfcb)(0, 0, buf, fmt, va);
#endif
  va_end(va);
  return result;
}

int snprintf_z(char *buf, int count, char const *fmt, ...) {
  int result;
  va_list va;
  va_start(va, fmt);
#ifdef USE_STD_SNPRINTF
  result = std::vsnprintf(buf, count, fmt, va);
  // stbsp_snprintf always returns a zero-terminated string
  buf[std::min(result, count-1)] = '\0';
#else
  result = STB_SPRINTF_DECORATE(vsnprintf)(buf, count, fmt, va);
#endif
  va_end(va);
  return result;
}

}  // namespace gemmi
