// Copyright Global Phasing Ltd.

#include <gemmi/gz.hpp>
#include <cassert>
#include <cstdio>       // fseek, ftell, fread
#include <climits>      // INT_MAX
#if USE_ZLIB_NG
# define WITH_GZFILEOP 1
# include <zlib-ng.h>
# define GG(name) zng_ ## name
#else
# include <zlib.h>
# define GG(name) name
#endif
#include <gemmi/fileutil.hpp> // file_open

namespace gemmi {

const char* const zlib_description =
#if USE_ZLIB_NG
  "zlib-ng " ZLIBNG_VERSION;
#else
  "zlib " ZLIB_VERSION;
#endif

// Throws if the size is not found or if it is suspicious.
// Anything outside of the arbitrary limits from 1 to 10x of the compressed
// size looks suspicious to us.
// **This function should not be relied upon.**
// In particular, if the return values is >= 4GiB - it's only a guess.
size_t estimate_uncompressed_size(const std::string& path) {
  fileptr_t f = file_open(path.c_str(), "rb");
  unsigned char buf[4];
  if (std::fread(buf, 1, 2, f.get()) != 2)
    sys_fail("Failed to read: " + path);
  if (buf[0] != 0x1f || buf[1] != 0x8b)
    fail("File not in the gzip format: " + path);
  if (std::fseek(f.get(), -4, SEEK_END) != 0)
    sys_fail("fseek() failed (empty file?): " + path);
  long pos = std::ftell(f.get());
  if (pos <= 0)
    sys_fail("ftell() failed on " + path);
  size_t gzipped_size = pos + 4;
  if (std::fread(buf, 1, 4, f.get()) != 4)
    sys_fail("Failed to read last 4 bytes of: " + path);
  unsigned orig_size = (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf[0];
  if (orig_size + 100 < gzipped_size || orig_size > 100 * gzipped_size) {
    // The size is stored as 32-bit number. If the original size exceeds 4GiB,
    // the stored number is modulo 4 GiB. So we just guess...
    constexpr size_t max_uint = 4294967295U;
    if (gzipped_size > max_uint / 6)
      return max_uint + (sizeof(size_t) > 4 ? orig_size : 0);
    fail("Cannot determine uncompressed size of " + path +
         "\nWould it be " + std::to_string(gzipped_size) + " -> " +
         std::to_string(orig_size) + " bytes?");
  }
  return orig_size;
}

static size_t big_gzread(gzFile file, void* buf, size_t len) {
#if USE_ZLIB_NG
  return GG(gzfread)(buf, 1, len, file);
#else
  // In zlib >= 1.2.9 we could use gzfread()
  size_t read_bytes = 0;
  while (len > INT_MAX) {
    int ret = gzread(file, buf, INT_MAX);
    read_bytes += ret;
    if (ret != INT_MAX)
      return read_bytes;
    len -= INT_MAX;
    buf = (char*) buf + INT_MAX;
  }
  read_bytes += gzread(file, buf, (unsigned) len);
  return read_bytes;
#endif
}

char* GzStream::gets(char* line, int size) {
  return GG(gzgets)((gzFile)f, line, size);
}

int GzStream::getc() {
  return GG(gzgetc)((gzFile)f);
}

bool GzStream::read(void* buf, size_t len) {
  return big_gzread((gzFile)f, buf, len) == len;
}

bool GzStream::skip(size_t n) {
  return GG(gzseek)((gzFile)f, n, SEEK_CUR) != -1;
}

long GzStream::tell() {
  return GG(gztell)((gzFile)f);
}

std::string GzStream::read_rest() {
    std::string retval;
    int c = getc();
    if (c != EOF) {
      retval += (char)c;
      char buf[512];
      for (;;) {
        size_t n = big_gzread((gzFile)f, buf,  sizeof(buf));
        retval.append(buf, n);
        if (n != sizeof(buf))
          break;
      }
    }
    return retval;
}


MaybeGzipped::MaybeGzipped(const std::string& path) : BasicInput(path) {}

MaybeGzipped::~MaybeGzipped() {
  if (file_)
#if USE_ZLIB_NG || (ZLIB_VERNUM >= 0x1235)
    GG(gzclose_r)((gzFile)file_);
#else
    gzclose((gzFile)file_);
#endif
}

size_t MaybeGzipped::gzread_checked(void* buf, size_t len) {
  gzFile file = (gzFile) file_;
  size_t read_bytes = big_gzread(file, buf, len);
  if (read_bytes != len && !GG(gzeof)(file)) {
    int errnum = 0;
    std::string err_str = GG(gzerror)(file, &errnum);
    if (errnum == Z_ERRNO)
      sys_fail("failed to read " + path());
    if (errnum)
      fail("Error reading " + path() + ": " + err_str);
  }
  if (read_bytes > len)  // should never happen
    fail("Error reading " + path());
  return read_bytes;
}

CharArray MaybeGzipped::uncompress_into_buffer(size_t limit) {
  if (!is_compressed())
    return BasicInput::uncompress_into_buffer();
  size_t size = (limit == 0 ? estimate_uncompressed_size(path()) : limit);
  file_ = GG(gzopen)(path().c_str(), "rb");
  if (!file_)
    sys_fail("Failed to gzopen " + path());
  if (size > 3221225471)
    // if this exception is changed adjust prog/cif2mtz.cpp
    fail("For now gz files above 3 GiB uncompressed are not supported.\n"
         "To read " + path() + " first uncompress it.");
  CharArray mem(size);
  size_t read_bytes = gzread_checked(mem.data(), size);
  // if the file is shorter than the size from header, adjust size
  if (read_bytes < size) {
    mem.set_size(read_bytes);  // should we call resize() here
  } else if (limit == 0) { // read_bytes == size
  // if the file is longer than the size from header, read in the rest
    int next_char;
    while (!GG(gzeof)((gzFile)file_) && (next_char = GG(gzgetc)((gzFile)file_)) != -1) {
      if (mem.size() > 3221225471)
        fail("For now gz files above 3 GiB uncompressed are not supported.\n"
             "To read " + path() + " first uncompress it.");
      GG(gzungetc)(next_char, (gzFile)file_);
      size_t old_size = mem.size();
      mem.resize(2 * old_size);
      size_t n = gzread_checked(mem.data() + old_size, old_size);
      mem.set_size(old_size + n);
    }
  }
  return mem;
}

std::unique_ptr<AnyStream> MaybeGzipped::create_stream() {
  if (is_compressed()) {
    file_ = GG(gzopen)(path().c_str(), "rb");
    if (!file_)
      sys_fail("Failed to gzopen " + path());
#if ZLIB_VERNUM >= 0x1235
    GG(gzbuffer)((gzFile)file_, 64*1024);
#endif
    return std::unique_ptr<AnyStream>(new GzStream(file_));
  }
  return BasicInput::create_stream();
}

} // namespace gemmi
