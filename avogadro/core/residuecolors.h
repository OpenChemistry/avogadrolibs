#ifndef AVOGADRO_CORE_RESIDUE_COLORS
#define AVOGADRO_CORE_RESIDUE_COLORS

namespace Avogadro {
namespace Core {

unsigned char chain_color[][3] = {
  // See, for example http://jmol.sourceforge.net/jscolors/index.en.html
  // # A             # B                 # C            # D
  { 192, 208, 255 },{ 176, 255, 176 },{ 255, 192, 200 },{ 204, 128, 255 },
  // # E             # F                 # G           #  H
  { 255, 192, 255 },{ 176, 240, 240 },{ 255, 208, 112 },{ 240, 128, 128 },
  // # I             # J                 # K            # L
  { 245, 222, 179 },{ 0, 191, 255 },  { 205, 92, 92 },  { 102, 205, 170 },
  // # M             # N                 # O            # P
  { 154, 205, 50 }, { 238, 130, 238 },{ 0, 206, 209 },  { 0, 255, 127 },
  // # Q             # R                 # S            # T
  { 60, 179, 113 }, { 0, 0, 139 },   { 189, 183, 107 }, { 0, 100, 0 },
  // # U             # V                 # W            # X
  { 128, 0, 0 },    { 128, 128, 0 }, { 128, 128, 0 },   { 0, 128, 128 },
  // # Y             # Z
  { 184, 134, 11 }, { 178, 34, 34 }
};

} // namespace Core
} // namespace Avogadro

#endif
