/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <avogadro/io/compressedstream.h>
#include <avogadro/io/compression.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <istream>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>

using Avogadro::Io::CompressingOStream;
using Avogadro::Io::Compression;
using Avogadro::Io::compressionSupported;
using Avogadro::Io::DecompressingIStream;

namespace {

constexpr std::uint64_t kFuzzSizeLimit = 8 * 1024 * 1024;

Compression codecFor(std::uint8_t selector)
{
  switch (selector % 4) {
    case 0:
      return Compression::Gzip;
    case 1:
      return Compression::Bzip2;
    case 2:
      return Compression::Xz;
    default:
      return Compression::Zstd;
  }
}

} // namespace

// Property under test: whatever we write, we can read back byte for byte.
// This is what catches flush and trailer bugs, which a decode-only target
// cannot reach because it never produces a valid stream of our own making.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  if (Size < 2)
    return 0;

  const Compression type = codecFor(Data[0]);
  if (!compressionSupported(type))
    return 0;

  // Slice the payload into writes of varying size, so partial put-area
  // flushes are exercised rather than a single bulk write.
  std::size_t slice = static_cast<std::size_t>(Data[1]) * 7 + 1;
  std::string payload(reinterpret_cast<const char*>(Data + 2), Size - 2);

  std::string encoded;
  {
    auto sink = std::unique_ptr<std::ostream>(new std::ostringstream());
    auto* raw = static_cast<std::ostringstream*>(sink.get());
    CompressingOStream out(std::move(sink), type);
    for (std::size_t pos = 0; pos < payload.size(); pos += slice) {
      const std::size_t n = std::min(slice, payload.size() - pos);
      out.write(payload.data() + pos, static_cast<std::streamsize>(n));
    }
    if (!out.finish())
      return 0; // encoder refused this input; not a round trip failure
    // Read the sink while the stream is still alive: it owns the sink and
    // destroys it.
    encoded = raw->str();
  }

  auto source = std::unique_ptr<std::istream>(
    new std::istringstream(encoded, std::ios::binary));
  DecompressingIStream in(std::move(source), type, kFuzzSizeLimit);
  std::string decoded((std::istreambuf_iterator<char>(in)),
                      std::istreambuf_iterator<char>());

  if (!in.error().empty()) {
    std::fprintf(stderr, "round trip reported an error: %s\n",
                 in.error().c_str());
    std::abort();
  }
  if (decoded != payload) {
    std::fprintf(stderr,
                 "round trip changed the data: wrote %zu bytes, read %zu\n",
                 payload.size(), decoded.size());
    std::abort();
  }

  return 0;
}
