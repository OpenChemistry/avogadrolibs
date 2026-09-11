/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_COMPRESSION_H
#define AVOGADRO_IO_COMPRESSION_H

#include "avogadroioexport.h"

#include <cstddef>
#include <string>
#include <vector>

namespace Avogadro::Io {

/**
 * @brief The compression codecs Avogadro can read and write.
 *
 * Everything in this header compiles whether or not the compression back ends
 * were available at build time, so callers never need to guard their code.
 * Use compressionAvailable() and compressionSupported() to find out what this
 * particular build can actually decode.
 */
enum class Compression
{
  None,
  Gzip,
  Bzip2,
  Xz,
  Zstd
};

/**
 * @brief Map a file extension to the codec it denotes.
 * @param extension The extension without a leading dot, in any case. Both
 * "zst" and "zstd" map to Compression::Zstd.
 * @return The codec, or Compression::None if the extension is not one of ours.
 */
AVOGADROIO_EXPORT Compression
compressionFromExtension(const std::string& extension);

/**
 * @brief The canonical file extension for a codec, without a leading dot.
 * @return "gz", "bz2", "xz" or "zst"; empty for Compression::None.
 */
AVOGADROIO_EXPORT std::string compressionExtension(Compression type);

/**
 * @brief A human readable codec name, for error messages.
 * @return "gzip", "bzip2", "xz" or "zstd"; empty for Compression::None.
 */
AVOGADROIO_EXPORT std::string compressionName(Compression type);

/**
 * @brief Every extension that denotes compression, without leading dots.
 *
 * Used to build file dialog filters. Currently gz, bz2, xz, zst and zstd.
 */
AVOGADROIO_EXPORT std::vector<std::string> compressionExtensions();

/**
 * @brief Remove a trailing compression extension from a file name.
 *
 * "water.xyz.gz" becomes "water.xyz", "water.xyz" is returned unchanged.
 * Only the final extension is considered and only when it is one of ours, so
 * "archive.tar.gz" becomes "archive.tar". Directory components are never
 * examined, so a path such as "/opt/v1.gz/water.xyz" is left alone.
 *
 * @param fileName The file name or path to examine.
 * @param type When non-null, set to the codec that was stripped, or
 * Compression::None when nothing was stripped.
 * @return The file name without the compression extension.
 */
AVOGADROIO_EXPORT std::string stripCompressionSuffix(
  const std::string& fileName, Compression* type = nullptr);

/**
 * @brief Identify a codec from the leading bytes of a file.
 *
 * This is the authoritative test. File names lie: structures downloaded from
 * the PDB and the COD are routinely gzipped under a plain name, so every read
 * path sniffs content and uses the name only to choose the chemical format.
 *
 * Magic numbers: gzip 1f 8b 08, bzip2 "BZh" followed by '1'-'9', xz
 * fd 37 7a 58 5a 00, zstd 28 b5 2f fd.
 *
 * @param data The start of the file. May be shorter than a magic number, in
 * which case the answer is Compression::None.
 * @param size The number of valid bytes in @a data.
 * @return The codec detected, or Compression::None.
 */
AVOGADROIO_EXPORT Compression detectCompression(const char* data,
                                                std::size_t size);

/**
 * @brief The number of bytes detectCompression() may examine.
 *
 * Read at least this many bytes before calling it, when that many exist.
 */
constexpr std::size_t compressionMagicSize = 6;

/**
 * @brief Was this build compiled with compression support at all?
 *
 * False in builds configured with USE_LIBARCHIVE=OFF, such as the Python
 * wheels. Reading a compressed file then fails with a clear error rather than
 * misparsing the compressed bytes.
 */
AVOGADROIO_EXPORT bool compressionAvailable();

/**
 * @brief Can this build decode and encode @a type?
 *
 * Availability varies by platform because it depends on which optional
 * libraries libarchive was built against. The macOS build has historically
 * shipped without liblzma, leaving xz unsupported. The answer is determined by
 * probing the back ends once, on first call, and is then cached.
 *
 * Gzip is handled by zlib rather than libarchive, so it is supported whenever
 * compressionAvailable() is true.
 *
 * @note libarchive will silently substitute an external helper program for a
 * codec it was not built with. Avogadro refuses that fallback, so that reading
 * a file never depends on what happens to be installed in the PATH and never
 * spawns a subprocess. Such a codec is reported as unsupported here.
 */
AVOGADROIO_EXPORT bool compressionSupported(Compression type);

/**
 * @brief Every codec this build can actually decode and encode.
 */
AVOGADROIO_EXPORT std::vector<Compression> supportedCompressions();

} // namespace Avogadro::Io

#endif // AVOGADRO_IO_COMPRESSION_H
