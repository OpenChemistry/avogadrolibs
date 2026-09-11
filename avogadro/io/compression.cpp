/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "compression.h"

#include <algorithm>
#include <cctype>

#ifdef AVO_USE_LIBARCHIVE
#include <archive.h>
#endif

namespace Avogadro::Io {

namespace {

std::string toLower(const std::string& value)
{
  std::string result(value);
  std::transform(
    result.begin(), result.end(), result.begin(),
    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return result;
}

} // namespace

Compression compressionFromExtension(const std::string& extension)
{
  std::string ext = toLower(extension);
  if (ext == "gz")
    return Compression::Gzip;
  if (ext == "bz2")
    return Compression::Bzip2;
  if (ext == "xz")
    return Compression::Xz;
  if (ext == "zst" || ext == "zstd")
    return Compression::Zstd;
  return Compression::None;
}

std::string compressionExtension(Compression type)
{
  switch (type) {
    case Compression::Gzip:
      return "gz";
    case Compression::Bzip2:
      return "bz2";
    case Compression::Xz:
      return "xz";
    case Compression::Zstd:
      return "zst";
    default:
      return std::string();
  }
}

std::string compressionName(Compression type)
{
  switch (type) {
    case Compression::Gzip:
      return "gzip";
    case Compression::Bzip2:
      return "bzip2";
    case Compression::Xz:
      return "xz";
    case Compression::Zstd:
      return "zstd";
    default:
      return std::string();
  }
}

std::vector<std::string> compressionExtensions()
{
  return { "gz", "bz2", "xz", "zst", "zstd" };
}

std::string stripCompressionSuffix(const std::string& fileName,
                                   Compression* type)
{
  if (type != nullptr)
    *type = Compression::None;

  // Only the final path component may have its suffix examined, so a dot in
  // a directory name (e.g. "/opt/v1.2/water.xyz") is never mistaken for an
  // extension.
  std::size_t sep = fileName.find_last_of("/\\");
  std::size_t baseStart = (sep == std::string::npos) ? 0 : sep + 1;

  std::size_t dot = fileName.find_last_of('.');

  // The dot must fall within the final path component, and it must not be
  // the first character of that component. A name such as ".gz" is a
  // dotfile with no extension at all, matching the usual "hidden file"
  // convention (compare ".gitignore", which nobody would call an extension
  // "gitignore" on an empty stem); it is left alone rather than stripped
  // down to an empty file name.
  if (dot == std::string::npos || dot < baseStart || dot == baseStart)
    return fileName;

  std::string extension = fileName.substr(dot + 1);
  Compression detected = compressionFromExtension(extension);
  if (detected == Compression::None)
    return fileName;

  if (type != nullptr)
    *type = detected;
  return fileName.substr(0, dot);
}

Compression detectCompression(const char* data, std::size_t size)
{
  if (data == nullptr)
    return Compression::None;

  auto byte = [data](std::size_t i) {
    return static_cast<unsigned char>(data[i]);
  };

  if (size >= 3 && byte(0) == 0x1f && byte(1) == 0x8b && byte(2) == 0x08)
    return Compression::Gzip;

  if (size >= 4 && byte(0) == 'B' && byte(1) == 'Z' && byte(2) == 'h' &&
      byte(3) >= '1' && byte(3) <= '9')
    return Compression::Bzip2;

  if (size >= 6 && byte(0) == 0xfd && byte(1) == 0x37 && byte(2) == 0x7a &&
      byte(3) == 0x58 && byte(4) == 0x5a && byte(5) == 0x00)
    return Compression::Xz;

  if (size >= 4 && byte(0) == 0x28 && byte(1) == 0xb5 && byte(2) == 0x2f &&
      byte(3) == 0xfd)
    return Compression::Zstd;

  return Compression::None;
}

bool compressionAvailable()
{
#ifdef AVO_USE_LIBARCHIVE
  return true;
#else
  return false;
#endif
}

bool compressionSupported(Compression type)
{
  // Gzip is decoded and encoded with zlib directly (see compressedstream.cpp
  // for why), so its availability tracks whether this build was compiled
  // with the compression back ends at all, rather than a libarchive probe.
  if (type == Compression::Gzip)
    return compressionAvailable();

#ifdef AVO_USE_LIBARCHIVE
  // Registering an unsupported filter with libarchive is what installs its
  // "spawn an external helper program" fallback, so each codec is probed
  // exactly once, on a throwaway handle, and the result cached. A codec must
  // pass both the read and the write probe: ARCHIVE_WARN ("will use an
  // external program") counts as unsupported for both directions, since we
  // refuse to depend on what happens to be installed in PATH.
  static const bool bzip2Supported = [] {
    struct archive* read = archive_read_new();
    int readResult = archive_read_support_filter_bzip2(read);
    archive_read_free(read);
    struct archive* write = archive_write_new();
    int writeResult = archive_write_add_filter_bzip2(write);
    archive_write_free(write);
    return readResult == ARCHIVE_OK && writeResult == ARCHIVE_OK;
  }();

  static const bool xzSupported = [] {
    struct archive* read = archive_read_new();
    int readResult = archive_read_support_filter_xz(read);
    archive_read_free(read);
    struct archive* write = archive_write_new();
    int writeResult = archive_write_add_filter_xz(write);
    archive_write_free(write);
    return readResult == ARCHIVE_OK && writeResult == ARCHIVE_OK;
  }();

  static const bool zstdSupported = [] {
    struct archive* read = archive_read_new();
    int readResult = archive_read_support_filter_zstd(read);
    archive_read_free(read);
    struct archive* write = archive_write_new();
    int writeResult = archive_write_add_filter_zstd(write);
    archive_write_free(write);
    return readResult == ARCHIVE_OK && writeResult == ARCHIVE_OK;
  }();

  switch (type) {
    case Compression::Bzip2:
      return bzip2Supported;
    case Compression::Xz:
      return xzSupported;
    case Compression::Zstd:
      return zstdSupported;
    default:
      return false;
  }
#else
  return false;
#endif
}

std::vector<Compression> supportedCompressions()
{
  std::vector<Compression> result;
  for (Compression c : { Compression::Gzip, Compression::Bzip2, Compression::Xz,
                         Compression::Zstd }) {
    if (compressionSupported(c))
      result.push_back(c);
  }
  return result;
}

} // namespace Avogadro::Io
