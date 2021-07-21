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

unsigned char amino_color[][3] = {
    // See, for example http://jmol.sourceforge.net/jscolors/index.en.html
    // # Ala            # Arg             # Asn            # Asp
    { 200, 200, 200 },{ 20, 90, 255 },{ 0, 220, 220 },{ 230, 10, 10 },
    // # Cys            # Gln             # Glu             # Gly
    { 230, 230, 0 },{ 0, 220, 220 },{ 230, 10, 10 },{ 235, 235, 235 },
    // # His            # Ile             # Leu             # Lys
    { 130, 130, 255 },{ 15, 130, 15 },{ 15, 130, 15 },{ 20, 90, 255 },
    // # Met            # Phe             # Pro             # Ser
    { 230, 230, 0 },{ 50, 50, 170 },{ 220, 150, 130 },{ 250, 150, 0 },
    // # Thr            # Trp             # Tyr            # Val
    { 250, 150, 0 },{ 180, 90, 180 },{ 50, 50, 170 },{ 15, 130, 15 },
    // # Asx            # Glx           # Anything else
    { 255, 105, 180 },{ 255, 105, 180 }, { 190, 160, 110}
};

unsigned char shapely_color[][3] = {
    // See, for example http://jmol.sourceforge.net/jscolors/index.en.html
    // # Ala            # Arg             # Asn            # Asp
    { 140, 255, 140 },{ 0, 0, 124 },{ 255, 124, 112 },{ 160, 0, 66 },
    // # Cys            # Gln             # Glu             # Gly
    { 255, 255, 112 },{ 255, 76, 76 },{ 102, 0, 0 },{ 255, 255, 255 },
    // # His            # Ile             # Leu             # Lys
    { 112, 112, 255 },{ 0, 76, 0 },{ 69, 94, 69 },{ 71, 71, 184 },
    // # Met            # Phe             # Pro             # Ser
    { 184, 160, 66 },{ 83, 76, 82 },{ 82, 82, 82 },{ 255, 112, 66 },
    // # Thr            # Trp             # Tyr            # Val
    { 184, 76, 0 },{ 79, 70, 0 },{ 140, 112, 76 },{ 255, 140, 255 },
    // # Asx            # Glx           # Anything else
    { 255, 0, 255 },{ 255, 0, 255 }, { 255, 0, 255}
};

unsigned char secondary_color[][3] = {
    // See, for example http://jmol.sourceforge.net/jscolors/index.en.html
    // using codes from MMTF
    // 0 = pi "I"  # bend "S"   # alpha "H"  # beta "E"
    { 96, 0, 128 },{  255, 255, 255 },{  255, 0, 128 },  {  255, 200, 0 },
    // 4 = 3-10 "G" # bridge "B" # turn "T"  # coil "C"
    { 160, 0, 128 },{  255, 255, 255 },{  96, 128, 255 },  {  255, 255, 255 }
};

} // namespace Core
} // namespace Avogadro

#endif
