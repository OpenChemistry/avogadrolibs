// Copyright 2018 Global Phasing Ltd.
//
// File-related utilities.

#ifndef GEMMI_FILEUTIL_HPP_
#define GEMMI_FILEUTIL_HPP_

#include <cassert>
#include <cstdio>    // for FILE, fopen, fclose
#include <cstdint>
#include <cstdlib>   // for malloc, realloc
#include <cstring>   // for strlen
#include <initializer_list>
#include <memory>    // for unique_ptr
#include "fail.hpp"  // for sys_fail

#if defined(_WIN32) && !defined(GEMMI_USE_FOPEN)
#include "utf.hpp"
#endif

namespace gemmi {

/// Extract basename from path, optionally stripping directory and suffixes.
/// @brief Extract filename with optional suffix removal.
/// @param path full file path
/// @param exts list of file extensions to strip from basename
/// @return basename without directory path and specified extensions
inline std::string path_basename(const std::string& path,
                                 std::initializer_list<const char*> exts) {
  size_t pos = path.find_last_of("\\/");
  std::string basename = pos == std::string::npos ? path : path.substr(pos + 1);
  for (const char* ext : exts) {
    size_t len = std::strlen(ext);
    if (basename.size() > len &&
        basename.compare(basename.length() - len, len, ext, len) == 0)
      basename.resize(basename.length() - len);
  }
  return basename;
}

// file operations

/// @brief Custom deleter for FILE* pointers.
/// @details Conditionally calls std::fclose based on use_fclose flag.
struct needs_fclose {
  /// Whether to call fclose when deleting.
  bool use_fclose;
  /// Delete operator that optionally calls std::fclose.
  /// @brief Delete FILE* pointer if use_fclose is true.
  /// @param f FILE pointer to delete
  void operator()(std::FILE* f) const noexcept {
    if (use_fclose)
      std::fclose(f);
  }
};

/// @brief Unique pointer to FILE with custom deleter.
typedef std::unique_ptr<std::FILE, needs_fclose> fileptr_t;

/// Open a file and return a managed pointer.
/// @brief Open file with UTF-8 filename support and error handling.
/// @param path UTF-8 encoded file path
/// @param mode file open mode (e.g., "rb", "wb")
/// @return managed FILE pointer that auto-closes on destruction
/// @throws std::runtime_error if file cannot be opened
inline fileptr_t file_open(const char* path, const char* mode) {
  std::FILE* file;
#if defined(_WIN32) && !defined(GEMMI_USE_FOPEN)
  std::wstring wpath = UTF8_to_wchar(path);
  std::wstring wmode = UTF8_to_wchar(mode);
  if ((file = ::_wfopen(wpath.c_str(), wmode.c_str())) == nullptr)
#else
  if ((file = std::fopen(path, mode)) == nullptr)
#endif
    sys_fail(std::string("Failed to open ") + path +
             (*mode == 'w' ? " for writing" : ""));
  return fileptr_t(file, needs_fclose{true});
}

/// Open a file, returning null pointer on failure instead of throwing.
/// @brief Open file without exception on error.
/// @param path UTF-8 encoded file path
/// @param mode file open mode (e.g., "rb", "wb")
/// @return managed FILE pointer or empty pointer if open fails
inline fileptr_t file_open_or_null(const char* path, const char* mode) {
  std::FILE* file;
#if defined(_WIN32) && !defined(GEMMI_USE_FOPEN)
  std::wstring wpath = UTF8_to_wchar(path);
  std::wstring wmode = UTF8_to_wchar(mode);
  file = ::_wfopen(wpath.c_str(), wmode.c_str());
#else
  file = std::fopen(path, mode);
#endif
  return fileptr_t(file, needs_fclose{true});
}

/// Open a file, treating "-" as stdin/stdout.
/// @brief Open file or return predefined stream for dash character.
/// @param path file path, or "-" for stdin/stdout
/// @param mode file open mode (e.g., "rb" or "wb")
/// @param dash_stream stream to use when path is "-"
/// @return managed FILE pointer (either opened file or dash_stream)
inline fileptr_t file_open_or(const char* path, const char* mode,
                              std::FILE* dash_stream) {
  if (path[0] == '-' && path[1] == '\0')
    return fileptr_t(dash_stream, needs_fclose{false});
  return file_open(path, mode);
}

/// Get file size by seeking to end and back.
/// @brief Determine file size in bytes.
/// @param f open FILE pointer
/// @param path file path (used only for error messages)
/// @return file size in bytes
/// @throws std::runtime_error if seek or tell operations fail
inline std::size_t file_size(std::FILE* f, const std::string& path) {
  if (std::fseek(f, 0, SEEK_END) != 0)
    sys_fail(path + ": fseek failed");
  long length = std::ftell(f);
  if (length < 0)
    sys_fail(path + ": ftell failed");
  if (std::fseek(f, 0, SEEK_SET) != 0)
    sys_fail(path + ": fseek failed");
  return length;
}

// helper functions for working with binary files

/// Check if platform is little-endian.
/// @brief Test platform byte order.
/// @return true if platform is little-endian, false if big-endian
inline bool is_little_endian() {
  std::uint32_t x = 1;
  return *reinterpret_cast<char *>(&x) == 1;
}

/// Swap bytes in a 2-byte value.
/// @brief Reverse byte order of a short integer.
/// @param start pointer to 2-byte value to swap in-place
inline void swap_two_bytes(void* start) {
  char* bytes = static_cast<char*>(start);
  std::swap(bytes[0], bytes[1]);
}

/// Swap bytes in a 4-byte value.
/// @brief Reverse byte order of a 32-bit integer.
/// @param start pointer to 4-byte value to swap in-place
inline void swap_four_bytes(void* start) {
  char* bytes = static_cast<char*>(start);
  std::swap(bytes[0], bytes[3]);
  std::swap(bytes[1], bytes[2]);
}

/// Swap bytes in an 8-byte value.
/// @brief Reverse byte order of a 64-bit integer or double.
/// @param start pointer to 8-byte value to swap in-place
inline void swap_eight_bytes(void* start) {
  char* bytes = static_cast<char*>(start);
  std::swap(bytes[0], bytes[7]);
  std::swap(bytes[1], bytes[6]);
  std::swap(bytes[2], bytes[5]);
  std::swap(bytes[3], bytes[4]);
}


/// @brief Dynamically allocated character buffer.
/// @details Manages memory using std::malloc/std::realloc/std::free.
class CharArray {
  std::unique_ptr<char, decltype(&std::free)> ptr_;
  size_t size_;
public:
  /// Create an empty buffer.
  /// @brief Default constructor for zero-sized buffer.
  CharArray() : ptr_(nullptr, &std::free), size_(0) {}
  /// Create a buffer of specified size.
  /// @brief Allocate buffer of given size.
  /// @param n buffer size in bytes
  explicit CharArray(size_t n) : ptr_((char*)std::malloc(n), &std::free), size_(n) {}
  /// Check if buffer is allocated.
  /// @brief Test whether buffer contains valid memory.
  /// @return true if buffer is not null
  explicit operator bool() const { return (bool)ptr_; }
  /// Access buffer data.
  /// @brief Get writable pointer to buffer.
  /// @return pointer to buffer data
  char* data() { return ptr_.get(); }
  /// Access buffer data (const).
  /// @brief Get read-only pointer to buffer.
  /// @return const pointer to buffer data
  const char* data() const { return ptr_.get(); }
  /// Get buffer size.
  /// @brief Return current buffer size in bytes.
  /// @return buffer size
  size_t size() const { return size_; }
  /// Change recorded buffer size.
  /// @brief Update internal size without reallocating.
  /// @param n new size value
  void set_size(size_t n) { size_ = n; }

  /// Resize buffer to new size.
  /// @brief Reallocate buffer to given size.
  /// @param n new buffer size in bytes
  /// @throws std::runtime_error if reallocation fails and n is non-zero
  void resize(size_t n) {
    char* new_ptr = (char*) std::realloc(ptr_.get(), n);
    if (!new_ptr && n != 0)
      fail("Out of memory.");
    (void) ptr_.release();  // NOLINT(bugprone-unused-return-value)
    ptr_.reset(new_ptr);
    size_ = n;
  }

  /// Remove first n bytes and shift remaining data.
  /// @brief Roll buffer forward by removing leading bytes.
  /// @param n number of bytes to remove from start
  /// @return pointer to space at end for new data
  char* roll(size_t n) {
    assert(n <= size());
    std::memmove(data(), data() + n, n);
    return data() + n;
  }
};


/// Read entire file into a memory buffer.
/// @brief Load file contents into CharArray (uses fseek for size determination).
/// @param path UTF-8 file path to read
/// @return CharArray containing file data
/// @throws std::runtime_error if file cannot be opened or read
inline CharArray read_file_into_buffer(const std::string& path) {
  fileptr_t f = file_open(path.c_str(), "rb");
  size_t size = file_size(f.get(), path);
  CharArray buffer(size);
  if (std::fread(buffer.data(), size, 1, f.get()) != 1)
    sys_fail(path + ": fread failed");
  return buffer;
}

/// Read stdin into a memory buffer.
/// @brief Load standard input into CharArray.
/// @return CharArray containing stdin data
/// @throws std::runtime_error if read operation fails
inline CharArray read_stdin_into_buffer() {
  size_t n = 0;
  CharArray buffer(16 * 1024);
  for (;;) {
    n += std::fread(buffer.data() + n, 1, buffer.size() - n, stdin);
    if (n != buffer.size()) {
      buffer.set_size(n);
      break;
    }
    buffer.resize(2*n);
  }
  return buffer;
}

/// Read input (file, gzip, or stdin) into a buffer.
/// @brief Intelligently read various input sources into CharArray.
/// @tparam T input type (typically BasicInput or derived)
/// @param input input object with is_compressed(), is_stdin(), and path() methods
/// @return CharArray containing input data
template<typename T>
inline CharArray read_into_buffer(T&& input) {
  if (input.is_compressed())
    return input.uncompress_into_buffer();
  if (input.is_stdin())
    return read_stdin_into_buffer();
  return read_file_into_buffer(input.path());
}

} // namespace gemmi
#endif
