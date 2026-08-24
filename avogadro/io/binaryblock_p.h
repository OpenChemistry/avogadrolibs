/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_BINARYBLOCK_P_H
#define AVOGADRO_IO_BINARYBLOCK_P_H

#include <algorithm>
#include <cstddef>
#include <ios>
#include <istream>
#include <vector>

namespace Avogadro::Io {

/**
 * Read exactly @a n bytes of @a in into @a buff, growing it to fit.
 *
 * The binary trajectory formats (DCD, TRR) take every block length from the
 * file itself, so those lengths are attacker-controlled -- DCD's NTITLE scales
 * by 80, TRR's string length is used raw. Both formats used to read straight
 * into a fixed char[BUFSIZ], and any length past that wrote down the stack.
 *
 * Two rules make that impossible here:
 *   - the buffer grows to the requested size, so a read never runs past it;
 *   - a length greater than @a fileLen is refused outright, since no block can
 *     be larger than the file that contains it. That also stops a corrupt
 *     header from reserving gigabytes.
 *
 * On failure the buffer is zeroed rather than left holding the previous block,
 * so a truncated file yields deterministic zeros instead of stale data, and
 * the stream is marked exhausted: both readers drive their frame loops from
 * tellg(), and a refusal that consumed nothing would otherwise leave the
 * position unchanged and spin forever.
 *
 * @return True if @a n bytes were read.
 */
inline bool readBlock(std::istream& in, std::vector<char>& buff,
                      std::streamsize n, std::streamsize fileLen)
{
  if (n >= 0 && n <= fileLen) {
    if (static_cast<std::size_t>(n) > buff.size())
      buff.resize(static_cast<std::size_t>(n));
    in.read(buff.data(), n);
    if (in.gcount() == n)
      return true;
  }

  std::fill(buff.begin(), buff.end(), '\0');
  in.setstate(std::ios::eofbit | std::ios::failbit);
  return false;
}

} // namespace Avogadro::Io

#endif // AVOGADRO_IO_BINARYBLOCK_P_H
