/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <avogadro/io/compressedstream.h>
#include <avogadro/io/compression.h>

#include <cstdint>
#include <istream>
#include <memory>
#include <sstream>
#include <string>

using Avogadro::Io::Compression;
using Avogadro::Io::DecompressingIStream;
using Avogadro::Io::detectCompression;

namespace {

// Decompressed data is held in memory so the stream can seek, so an
// unbounded limit would let the fuzzer trivially exhaust the machine with a
// decompression bomb rather than finding real bugs. 1 MiB is plenty to cross
// several 64 KiB chunk boundaries.
constexpr std::uint64_t kFuzzSizeLimit = 1024 * 1024;

// Drain the stream in one of several access patterns. Sequential reading
// alone would never touch the seek paths, and those carry the chunk
// arithmetic most likely to be wrong.
void exercise(DecompressingIStream& stream, std::uint8_t pattern,
              const std::string& input)
{
  switch (pattern % 5) {
    case 0: { // straight slurp
      std::string all((std::istreambuf_iterator<char>(stream)),
                      std::istreambuf_iterator<char>());
      (void)all;
      break;
    }
    case 1: { // measure first, as DCD and TRR do, then read
      stream.seekg(0, std::ios::end);
      std::streampos size = stream.tellg();
      stream.clear();
      stream.seekg(0);
      std::string all((std::istreambuf_iterator<char>(stream)),
                      std::istreambuf_iterator<char>());
      (void)size;
      (void)all;
      break;
    }
    case 2: { // seeks driven by the input itself
      for (std::size_t i = 0; i < input.size() && i < 64; ++i) {
        stream.clear();
        stream.seekg(static_cast<std::streamoff>(
          static_cast<unsigned char>(input[i]) * 977));
        char buffer[32];
        stream.read(buffer, sizeof(buffer));
      }
      break;
    }
    case 3: { // line oriented, like most chemical formats
      std::string line;
      while (std::getline(stream, line)) {}
      break;
    }
    default: { // one byte at a time, with the occasional putback
      int count = 0;
      while (stream.good() && count < (1 << 16)) {
        int c = stream.get();
        if (c == std::istream::traits_type::eof())
          break;
        if ((count & 0xff) == 0)
          stream.unget();
        ++count;
      }
      break;
    }
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  if (Size < 1)
    return 0;

  const std::uint8_t pattern = Data[0];
  std::string input(reinterpret_cast<const char*>(Data + 1), Size - 1);

  // Only feed the decoder data it would actually be handed: the real read
  // paths sniff first and only wrap when a magic number matched.
  Compression type = detectCompression(input.data(), input.size());
  if (type == Compression::None)
    return 0;

  auto source = std::unique_ptr<std::istream>(
    new std::istringstream(input, std::ios::binary));
  DecompressingIStream stream(std::move(source), type, kFuzzSizeLimit);

  exercise(stream, pattern, input);

  // Reading the error is part of the contract every caller follows.
  (void)stream.error();
  (void)stream.decodedSize();
  (void)stream.hitSizeLimit();

  return 0;
}
