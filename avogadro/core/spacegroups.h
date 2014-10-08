/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2014 Albert DeFusco, University of Pittsburgh

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_CORE_SPACEGROUPS_H
#define AVOGADRO_CORE_SPACEGROUPS_H

#include "avogadrocore.h"
#include <string>
#include <vector>

namespace Avogadro {
namespace Core {
//class Molecule;
//class UnitCell;

/**
 * @class SpaceGroups
 * @brief borrowed from spglib
 */
class AVOGADROCORE_EXPORT SpaceGroups
{
public:
  enum crystalSystem{NONE, TRICLI, MONOCLI, ORTHO, TETRA, TRIGO, RHOMB, HEXA, CUBIC};

  static std::string getInternational(int hallNumber);
  static std::string getInternationalFull(int hallNumber);
  static std::string getInternationalShort(int hallNumber);
  static std::string getBravais(int hallNumber);
  static std::string getSchoenflies(int hallNumber);
  static int getNumber(int hallNumber);
  static std::string getHallSymbol(int hallNumber);
  static std::string getSetting(int hallNumber);
  static std::string getCrystalSystem(int hallNumber);
  static void describeSpaceGroup(int hallNumber);
  static std::vector<std::string> getBravaisArray(crystalSystem crys);
  static std::vector<crystalSystem> getCrystalArray();
  static std::string getCrystalString(crystalSystem crystal);
  static std::vector<std::string> getIntSymbolArray(crystalSystem crystal,std::string bravais);
  static std::vector<std::string> getSettingArray(crystalSystem crystal, std::string bravais,std::string intSymbol);


  //static void getCrystalSystem(int hallNumber);
/* Copyright (C) 2010 Atsushi Togo */
  typedef struct {
    int number;
    char schoenflies[7];
    char hall_symbol[17];
    char international[32];
    char international_full[20];
    char international_short[11];
    char setting[6];
    crystalSystem holohedry;
  } SpaceGroupType;
  //static const SpaceGroupType spacegroup_types[];

private:
  SpaceGroups(); // not implemented
  ~SpaceGroups(); // not implemented


};

} // namespace Core
} // namespace Avogadro

//#include "spacegrouptypes.cpp"
/* In Hall symbols (3rd column), '=' is used instead of '"'. */
using Avogadro::Core::SpaceGroups;
const SpaceGroups::SpaceGroupType spacegroup_types[]= {
  {  0, "      ", "                ", "                               ", "                   ", "          ", "     ", SpaceGroups::NONE }, /*   0 */
  {  1, "C1^1  ", "P 1             ", "P 1                            ", "P 1                ", "P1        ", "     ", SpaceGroups::TRICLI }, /*   1 */
  {  2, "Ci^1  ", "-P 1            ", "P -1                           ", "P -1               ", "P-1       ", "     ", SpaceGroups::TRICLI }, /*   2 */
  {  3, "C2^1  ", "P 2y            ", "P 2 = P 1 2 1                  ", "P 1 2 1            ", "P2        ", "b    ", SpaceGroups::MONOCLI }, /*   3 */
  {  3, "C2^1  ", "P 2             ", "P 2 = P 1 1 2                  ", "P 1 1 2            ", "P2        ", "c    ", SpaceGroups::MONOCLI }, /*   4 */
  {  3, "C2^1  ", "P 2x            ", "P 2 = P 2 1 1                  ", "P 2 1 1            ", "P2        ", "a    ", SpaceGroups::MONOCLI }, /*   5 */
  {  4, "C2^2  ", "P 2yb           ", "P 2_1 = P 1 2_1 1              ", "P 1 2_1 1          ", "P2_1      ", "b    ", SpaceGroups::MONOCLI }, /*   6 */
  {  4, "C2^2  ", "P 2c            ", "P 2_1 = P 1 1 2_1              ", "P 1 1 2_1          ", "P2_1      ", "c    ", SpaceGroups::MONOCLI }, /*   7 */
  {  4, "C2^2  ", "P 2xa           ", "P 2_1 = P 2_1 1 1              ", "P 2_1 1 1          ", "P2_1      ", "a    ", SpaceGroups::MONOCLI }, /*   8 */
  {  5, "C2^3  ", "C 2y            ", "C 2 = C 1 2 1                  ", "C 1 2 1            ", "C2        ", "b1   ", SpaceGroups::MONOCLI }, /*   9 */
  {  5, "C2^3  ", "A 2y            ", "C 2 = A 1 2 1                  ", "A 1 2 1            ", "C2        ", "b2   ", SpaceGroups::MONOCLI }, /*  10 */
  {  5, "C2^3  ", "I 2y            ", "C 2 = I 1 2 1                  ", "I 1 2 1            ", "C2        ", "b3   ", SpaceGroups::MONOCLI }, /*  11 */
  {  5, "C2^3  ", "A 2             ", "C 2 = A 1 1 2                  ", "A 1 1 2            ", "C2        ", "c1   ", SpaceGroups::MONOCLI }, /*  12 */
  {  5, "C2^3  ", "B 2             ", "C 2 = B 1 1 2 = B 2            ", "B 1 1 2            ", "C2        ", "c2   ", SpaceGroups::MONOCLI }, /*  13 */
  {  5, "C2^3  ", "I 2             ", "C 2 = I 1 1 2                  ", "I 1 1 2            ", "C2        ", "c3   ", SpaceGroups::MONOCLI }, /*  14 */
  {  5, "C2^3  ", "B 2x            ", "C 2 = B 2 1 1                  ", "B 2 1 1            ", "C2        ", "a1   ", SpaceGroups::MONOCLI }, /*  15 */
  {  5, "C2^3  ", "C 2x            ", "C 2 = C 2 1 1                  ", "C 2 1 1            ", "C2        ", "a2   ", SpaceGroups::MONOCLI }, /*  16 */
  {  5, "C2^3  ", "I 2x            ", "C 2 = I 2 1 1                  ", "I 2 1 1            ", "C2        ", "a3   ", SpaceGroups::MONOCLI }, /*  17 */
  {  6, "Cs^1  ", "P -2y           ", "P m = P 1 m 1                  ", "P 1 m 1            ", "Pm        ", "b    ", SpaceGroups::MONOCLI }, /*  18 */
  {  6, "Cs^1  ", "P -2            ", "P m = P 1 1 m                  ", "P 1 1 m            ", "Pm        ", "c    ", SpaceGroups::MONOCLI }, /*  19 */
  {  6, "Cs^1  ", "P -2x           ", "P m = P m 1 1                  ", "P m 1 1            ", "Pm        ", "a    ", SpaceGroups::MONOCLI }, /*  20 */
  {  7, "Cs^2  ", "P -2yc          ", "P c = P 1 c 1                  ", "P 1 c 1            ", "Pc        ", "b1   ", SpaceGroups::MONOCLI }, /*  21 */
  {  7, "Cs^2  ", "P -2yac         ", "P c = P 1 n 1                  ", "P 1 n 1            ", "Pc        ", "b2   ", SpaceGroups::MONOCLI }, /*  22 */
  {  7, "Cs^2  ", "P -2ya          ", "P c = P 1 a 1                  ", "P 1 a 1            ", "Pc        ", "b3   ", SpaceGroups::MONOCLI }, /*  23 */
  {  7, "Cs^2  ", "P -2a           ", "P c = P 1 1 a                  ", "P 1 1 a            ", "Pc        ", "c1   ", SpaceGroups::MONOCLI }, /*  24 */
  {  7, "Cs^2  ", "P -2ab          ", "P c = P 1 1 n                  ", "P 1 1 n            ", "Pc        ", "c2   ", SpaceGroups::MONOCLI }, /*  25 */
  {  7, "Cs^2  ", "P -2b           ", "P c = P 1 1 b = P b            ", "P 1 1 b            ", "Pc        ", "c3   ", SpaceGroups::MONOCLI }, /*  26 */
  {  7, "Cs^2  ", "P -2xb          ", "P c = P b 1 1                  ", "P b 1 1            ", "Pc        ", "a1   ", SpaceGroups::MONOCLI }, /*  27 */
  {  7, "Cs^2  ", "P -2xbc         ", "P c = P n 1 1                  ", "P n 1 1            ", "Pc        ", "a2   ", SpaceGroups::MONOCLI }, /*  28 */
  {  7, "Cs^2  ", "P -2xc          ", "P c = P c 1 1                  ", "P c 1 1            ", "Pc        ", "a3   ", SpaceGroups::MONOCLI }, /*  29 */
  {  8, "Cs^3  ", "C -2y           ", "C m = C 1 m 1                  ", "C 1 m 1            ", "Cm        ", "b1   ", SpaceGroups::MONOCLI }, /*  30 */
  {  8, "Cs^3  ", "A -2y           ", "C m = A 1 m 1                  ", "A 1 m 1            ", "Cm        ", "b2   ", SpaceGroups::MONOCLI }, /*  31 */
  {  8, "Cs^3  ", "I -2y           ", "C m = I 1 m 1                  ", "I 1 m 1            ", "Cm        ", "b3   ", SpaceGroups::MONOCLI }, /*  32 */
  {  8, "Cs^3  ", "A -2            ", "C m = A 1 1 m                  ", "A 1 1 m            ", "Cm        ", "c1   ", SpaceGroups::MONOCLI }, /*  33 */
  {  8, "Cs^3  ", "B -2            ", "C m = B 1 1 m = B m            ", "B 1 1 m            ", "Cm        ", "c2   ", SpaceGroups::MONOCLI }, /*  34 */
  {  8, "Cs^3  ", "I -2            ", "C m = I 1 1 m                  ", "I 1 1 m            ", "Cm        ", "c3   ", SpaceGroups::MONOCLI }, /*  35 */
  {  8, "Cs^3  ", "B -2x           ", "C m = B m 1 1                  ", "B m 1 1            ", "Cm        ", "a1   ", SpaceGroups::MONOCLI }, /*  36 */
  {  8, "Cs^3  ", "C -2x           ", "C m = C m 1 1                  ", "C m 1 1            ", "Cm        ", "a2   ", SpaceGroups::MONOCLI }, /*  37 */
  {  8, "Cs^3  ", "I -2x           ", "C m = I m 1 1                  ", "I m 1 1            ", "Cm        ", "a3   ", SpaceGroups::MONOCLI }, /*  38 */
  {  9, "Cs^4  ", "C -2yc          ", "C c = C 1 c 1                  ", "C 1 c 1            ", "Cc        ", "b1   ", SpaceGroups::MONOCLI }, /*  39 */
  {  9, "Cs^4  ", "A -2yac         ", "C c = A 1 n 1                  ", "A 1 n 1            ", "Cc        ", "b2   ", SpaceGroups::MONOCLI }, /*  40 */
  {  9, "Cs^4  ", "I -2ya          ", "C c = I 1 a 1                  ", "I 1 a 1            ", "Cc        ", "b3   ", SpaceGroups::MONOCLI }, /*  41 */
  {  9, "Cs^4  ", "A -2ya          ", "C c = A 1 a 1                  ", "A 1 a 1            ", "Cc        ", "-b1  ", SpaceGroups::MONOCLI }, /*  42 */
  {  9, "Cs^4  ", "C -2ybc         ", "C c = C 1 n 1                  ", "C 1 n 1            ", "Cc        ", "-b2  ", SpaceGroups::MONOCLI }, /*  43 */
  {  9, "Cs^4  ", "I -2yc          ", "C c = I 1 c 1                  ", "I 1 c 1            ", "Cc        ", "-b3  ", SpaceGroups::MONOCLI }, /*  44 */
  {  9, "Cs^4  ", "A -2a           ", "C c = A 1 1 a                  ", "A 1 1 a            ", "Cc        ", "c1   ", SpaceGroups::MONOCLI }, /*  45 */
  {  9, "Cs^4  ", "B -2bc          ", "C c = B 1 1 n                  ", "B 1 1 n            ", "Cc        ", "c2   ", SpaceGroups::MONOCLI }, /*  46 */
  {  9, "Cs^4  ", "I -2b           ", "C c = I 1 1 b                  ", "I 1 1 b            ", "Cc        ", "c3   ", SpaceGroups::MONOCLI }, /*  47 */
  {  9, "Cs^4  ", "B -2b           ", "C c = B 1 1 b = B b            ", "B 1 1 b            ", "Cc        ", "-c1  ", SpaceGroups::MONOCLI }, /*  48 */
  {  9, "Cs^4  ", "A -2ac          ", "C c = A 1 1 n                  ", "A 1 1 n            ", "Cc        ", "-c2  ", SpaceGroups::MONOCLI }, /*  49 */
  {  9, "Cs^4  ", "I -2a           ", "C c = I 1 1 a                  ", "I 1 1 a            ", "Cc        ", "-c3  ", SpaceGroups::MONOCLI }, /*  50 */
  {  9, "Cs^4  ", "B -2xb          ", "C c = B b 1 1                  ", "B b 1 1            ", "Cc        ", "a1   ", SpaceGroups::MONOCLI }, /*  51 */
  {  9, "Cs^4  ", "C -2xbc         ", "C c = C n 1 1                  ", "C n 1 1            ", "Cc        ", "a2   ", SpaceGroups::MONOCLI }, /*  52 */
  {  9, "Cs^4  ", "I -2xc          ", "C c = I c 1 1                  ", "I c 1 1            ", "Cc        ", "a3   ", SpaceGroups::MONOCLI }, /*  53 */
  {  9, "Cs^4  ", "C -2xc          ", "C c = C c 1 1                  ", "C c 1 1            ", "Cc        ", "-a1  ", SpaceGroups::MONOCLI }, /*  54 */
  {  9, "Cs^4  ", "B -2xbc         ", "C c = B n 1 1                  ", "B n 1 1            ", "Cc        ", "-a2  ", SpaceGroups::MONOCLI }, /*  55 */
  {  9, "Cs^4  ", "I -2xb          ", "C c = I b 1 1                  ", "I b 1 1            ", "Cc        ", "-a3  ", SpaceGroups::MONOCLI }, /*  56 */
  { 10, "C2h^1 ", "-P 2y           ", "P 2/m = P 1 2/m 1              ", "P 1 2/m 1          ", "P2/m      ", "b    ", SpaceGroups::MONOCLI }, /*  57 */
  { 10, "C2h^1 ", "-P 2            ", "P 2/m = P 1 1 2/m              ", "P 1 1 2/m          ", "P2/m      ", "c    ", SpaceGroups::MONOCLI }, /*  58 */
  { 10, "C2h^1 ", "-P 2x           ", "P 2/m = P 2/m 1 1              ", "P 2/m 1 1          ", "P2/m      ", "a    ", SpaceGroups::MONOCLI }, /*  59 */
  { 11, "C2h^2 ", "-P 2yb          ", "P 2_1/m = P 1 2_1/m 1          ", "P 1 2_1/m 1        ", "P2_1/m    ", "b    ", SpaceGroups::MONOCLI }, /*  60 */
  { 11, "C2h^2 ", "-P 2c           ", "P 2_1/m = P 1 1 2_1/m          ", "P 1 1 2_1/m        ", "P2_1/m    ", "c    ", SpaceGroups::MONOCLI }, /*  61 */
  { 11, "C2h^2 ", "-P 2xa          ", "P 2_1/m = P 2_1/m 1 1          ", "P 2_1/m 1 1        ", "P2_1/m    ", "a    ", SpaceGroups::MONOCLI }, /*  62 */
  { 12, "C2h^3 ", "-C 2y           ", "C 2/m = C 1 2/m 1              ", "C 1 2/m 1          ", "C2/m      ", "b1   ", SpaceGroups::MONOCLI }, /*  63 */
  { 12, "C2h^3 ", "-A 2y           ", "C 2/m = A 1 2/m 1              ", "A 1 2/m 1          ", "C2/m      ", "b2   ", SpaceGroups::MONOCLI }, /*  64 */
  { 12, "C2h^3 ", "-I 2y           ", "C 2/m = I 1 2/m 1              ", "I 1 2/m 1          ", "C2/m      ", "b3   ", SpaceGroups::MONOCLI }, /*  65 */
  { 12, "C2h^3 ", "-A 2            ", "C 2/m = A 1 1 2/m              ", "A 1 1 2/m          ", "C2/m      ", "c1   ", SpaceGroups::MONOCLI }, /*  66 */
  { 12, "C2h^3 ", "-B 2            ", "C 2/m = B 1 1 2/m = B 2/m      ", "B 1 1 2/m          ", "C2/m      ", "c2   ", SpaceGroups::MONOCLI }, /*  67 */
  { 12, "C2h^3 ", "-I 2            ", "C 2/m = I 1 1 2/m              ", "I 1 1 2/m          ", "C2/m      ", "c3   ", SpaceGroups::MONOCLI }, /*  68 */
  { 12, "C2h^3 ", "-B 2x           ", "C 2/m = B 2/m 1 1              ", "B 2/m 1 1          ", "C2/m      ", "a1   ", SpaceGroups::MONOCLI }, /*  69 */
  { 12, "C2h^3 ", "-C 2x           ", "C 2/m = C 2/m 1 1              ", "C 2/m 1 1          ", "C2/m      ", "a2   ", SpaceGroups::MONOCLI }, /*  70 */
  { 12, "C2h^3 ", "-I 2x           ", "C 2/m = I 2/m 1 1              ", "I 2/m 1 1          ", "C2/m      ", "a3   ", SpaceGroups::MONOCLI }, /*  71 */
  { 13, "C2h^4 ", "-P 2yc          ", "P 2/c = P 1 2/c 1              ", "P 1 2/c 1          ", "P2/c      ", "b1   ", SpaceGroups::MONOCLI }, /*  72 */
  { 13, "C2h^4 ", "-P 2yac         ", "P 2/c = P 1 2/n 1              ", "P 1 2/n 1          ", "P2/c      ", "b2   ", SpaceGroups::MONOCLI }, /*  73 */
  { 13, "C2h^4 ", "-P 2ya          ", "P 2/c = P 1 2/a 1              ", "P 1 2/a 1          ", "P2/c      ", "b3   ", SpaceGroups::MONOCLI }, /*  74 */
  { 13, "C2h^4 ", "-P 2a           ", "P 2/c = P 1 1 2/a              ", "P 1 1 2/a          ", "P2/c      ", "c1   ", SpaceGroups::MONOCLI }, /*  75 */
  { 13, "C2h^4 ", "-P 2ab          ", "P 2/c = P 1 1 2/n              ", "P 1 1 2/n          ", "P2/c      ", "c2   ", SpaceGroups::MONOCLI }, /*  76 */
  { 13, "C2h^4 ", "-P 2b           ", "P 2/c = P 1 1 2/b = P 2/b      ", "P 1 1 2/b          ", "P2/c      ", "c3   ", SpaceGroups::MONOCLI }, /*  77 */
  { 13, "C2h^4 ", "-P 2xb          ", "P 2/c = P 2/b 1 1              ", "P 2/b 1 1          ", "P2/c      ", "a1   ", SpaceGroups::MONOCLI }, /*  78 */
  { 13, "C2h^4 ", "-P 2xbc         ", "P 2/c = P 2/n 1 1              ", "P 2/n 1 1          ", "P2/c      ", "a2   ", SpaceGroups::MONOCLI }, /*  79 */
  { 13, "C2h^4 ", "-P 2xc          ", "P 2/c = P 2/c 1 1              ", "P 2/c 1 1          ", "P2/c      ", "a3   ", SpaceGroups::MONOCLI }, /*  80 */
  { 14, "C2h^5 ", "-P 2ybc         ", "P 2_1/c = P 1 2_1/c 1          ", "P 1 2_1/c 1        ", "P2_1/c    ", "b1   ", SpaceGroups::MONOCLI }, /*  81 */
  { 14, "C2h^5 ", "-P 2yn          ", "P 2_1/c = P 1 2_1/n 1          ", "P 1 2_1/n 1        ", "P2_1/c    ", "b2   ", SpaceGroups::MONOCLI }, /*  82 */
  { 14, "C2h^5 ", "-P 2yab         ", "P 2_1/c = P 1 2_1/a 1          ", "P 1 2_1/a 1        ", "P2_1/c    ", "b3   ", SpaceGroups::MONOCLI }, /*  83 */
  { 14, "C2h^5 ", "-P 2ac          ", "P 2_1/c = P 1 1 2_1/a          ", "P 1 1 2_1/a        ", "P2_1/c    ", "c1   ", SpaceGroups::MONOCLI }, /*  84 */
  { 14, "C2h^5 ", "-P 2n           ", "P 2_1/c = P 1 1 2_1/n          ", "P 1 1 2_1/n        ", "P2_1/c    ", "c2   ", SpaceGroups::MONOCLI }, /*  85 */
  { 14, "C2h^5 ", "-P 2bc          ", "P 2_1/c = P 1 1 2_1/b = P 2_1/b", "P 1 1 2_1/b        ", "P2_1/c    ", "c3   ", SpaceGroups::MONOCLI }, /*  86 */
  { 14, "C2h^5 ", "-P 2xab         ", "P 2_1/c = P 2_1/b 1 1          ", "P 2_1/b 1 1        ", "P2_1/c    ", "a1   ", SpaceGroups::MONOCLI }, /*  87 */
  { 14, "C2h^5 ", "-P 2xn          ", "P 2_1/c = P 2_1/n 1 1          ", "P 2_1/n 1 1        ", "P2_1/c    ", "a2   ", SpaceGroups::MONOCLI }, /*  88 */
  { 14, "C2h^5 ", "-P 2xac         ", "P 2_1/c = P 2_1/c 1 1          ", "P 2_1/c 1 1        ", "P2_1/c    ", "a3   ", SpaceGroups::MONOCLI }, /*  89 */
  { 15, "C2h^6 ", "-C 2yc          ", "C 2/c = C 1 2/c 1              ", "C 1 2/c 1          ", "C2/c      ", "b1   ", SpaceGroups::MONOCLI }, /*  90 */
  { 15, "C2h^6 ", "-A 2yac         ", "C 2/c = A 1 2/n 1              ", "A 1 2/n 1          ", "C2/c      ", "b2   ", SpaceGroups::MONOCLI }, /*  91 */
  { 15, "C2h^6 ", "-I 2ya          ", "C 2/c = I 1 2/a 1              ", "I 1 2/a 1          ", "C2/c      ", "b3   ", SpaceGroups::MONOCLI }, /*  92 */
  { 15, "C2h^6 ", "-A 2ya          ", "C 2/c = A 1 2/a 1              ", "A 1 2/a 1          ", "C2/c      ", "-b1  ", SpaceGroups::MONOCLI }, /*  93 */
  { 15, "C2h^6 ", "-C 2ybc         ", "C 2/c = C 1 2/n 1              ", "C 1 2/n 1          ", "C2/c      ", "-b2  ", SpaceGroups::MONOCLI }, /*  94 */
  { 15, "C2h^6 ", "-I 2yc          ", "C 2/c = I 1 2/c 1              ", "I 1 2/c 1          ", "C2/c      ", "-b3  ", SpaceGroups::MONOCLI }, /*  95 */
  { 15, "C2h^6 ", "-A 2a           ", "C 2/c = A 1 1 2/a              ", "A 1 1 2/a          ", "C2/c      ", "c1   ", SpaceGroups::MONOCLI }, /*  96 */
  { 15, "C2h^6 ", "-B 2bc          ", "C 2/c = B 1 1 2/n              ", "B 1 1 2/n          ", "C2/c      ", "c2   ", SpaceGroups::MONOCLI }, /*  97 */
  { 15, "C2h^6 ", "-I 2b           ", "C 2/c = I 1 1 2/b              ", "I 1 1 2/b          ", "C2/c      ", "c3   ", SpaceGroups::MONOCLI }, /*  98 */
  { 15, "C2h^6 ", "-B 2b           ", "C 2/c = B 1 1 2/b = B 2/b      ", "B 1 1 2/b          ", "C2/c      ", "-c1  ", SpaceGroups::MONOCLI }, /*  99 */
  { 15, "C2h^6 ", "-A 2ac          ", "C 2/c = A 1 1 2/n              ", "A 1 1 2/n          ", "C2/c      ", "-c2  ", SpaceGroups::MONOCLI }, /* 100 */
  { 15, "C2h^6 ", "-I 2a           ", "C 2/c = I 1 1 2/a              ", "I 1 1 2/a          ", "C2/c      ", "-c3  ", SpaceGroups::MONOCLI }, /* 101 */
  { 15, "C2h^6 ", "-B 2xb          ", "C 2/c = B 2/b 1 1              ", "B 2/b 1 1          ", "C2/c      ", "a1   ", SpaceGroups::MONOCLI }, /* 102 */
  { 15, "C2h^6 ", "-C 2xbc         ", "C 2/c = C 2/n 1 1              ", "C 2/n 1 1          ", "C2/c      ", "a2   ", SpaceGroups::MONOCLI }, /* 103 */
  { 15, "C2h^6 ", "-I 2xc          ", "C 2/c = I 2/c 1 1              ", "I 2/c 1 1          ", "C2/c      ", "a3   ", SpaceGroups::MONOCLI }, /* 104 */
  { 15, "C2h^6 ", "-C 2xc          ", "C 2/c = C 2/c 1 1              ", "C 2/c 1 1          ", "C2/c      ", "-a1  ", SpaceGroups::MONOCLI }, /* 105 */
  { 15, "C2h^6 ", "-B 2xbc         ", "C 2/c = B 2/n 1 1              ", "B 2/n 1 1          ", "C2/c      ", "-a2  ", SpaceGroups::MONOCLI }, /* 106 */
  { 15, "C2h^6 ", "-I 2xb          ", "C 2/c = I 2/b 1 1              ", "I 2/b 1 1          ", "C2/c      ", "-a3  ", SpaceGroups::MONOCLI }, /* 107 */
  { 16, "D2^1  ", "P 2 2           ", "P 2 2 2                        ", "P 2 2 2            ", "P222      ", "     ", SpaceGroups::ORTHO }, /* 108 */
  { 17, "D2^2  ", "P 2c 2          ", "P 2 2 2_1                      ", "P 2 2 2_1          ", "P222_1    ", "     ", SpaceGroups::ORTHO }, /* 109 */
  { 17, "D2^2  ", "P 2a 2a         ", "P 2_1 2 2                      ", "P 2_1 2 2          ", "P2_122    ", "cab  ", SpaceGroups::ORTHO }, /* 110 */
  { 17, "D2^2  ", "P 2 2b          ", "P 2 2_1 2                      ", "P 2 2_1 2          ", "P22_12    ", "bca  ", SpaceGroups::ORTHO }, /* 111 */
  { 18, "D2^3  ", "P 2 2ab         ", "P 2_1 2_1 2                    ", "P 2_1 2_1 2        ", "P2_12_12  ", "     ", SpaceGroups::ORTHO }, /* 112 */
  { 18, "D2^3  ", "P 2bc 2         ", "P 2 2_1 2_1                    ", "P 2 2_1 2_1        ", "P22_12_1  ", "cab  ", SpaceGroups::ORTHO }, /* 113 */
  { 18, "D2^3  ", "P 2ac 2ac       ", "P 2_1 2 2_1                    ", "P 2_1 2 2_1        ", "P2_122_1  ", "bca  ", SpaceGroups::ORTHO }, /* 114 */
  { 19, "D2^4  ", "P 2ac 2ab       ", "P 2_1 2_1 2_1                  ", "P 2_1 2_1 2_1      ", "P2_12_12_1", "     ", SpaceGroups::ORTHO }, /* 115 */
  { 20, "D2^5  ", "C 2c 2          ", "C 2 2 2_1                      ", "C 2 2 2_1          ", "C222_1    ", "     ", SpaceGroups::ORTHO }, /* 116 */
  { 20, "D2^5  ", "A 2a 2a         ", "A 2_1 2 2                      ", "A 2_1 2 2          ", "A2_122    ", "cab  ", SpaceGroups::ORTHO }, /* 117 */
  { 20, "D2^5  ", "B 2 2b          ", "B 2 2_1 2                      ", "B 2 2_1 2          ", "B22_12    ", "bca  ", SpaceGroups::ORTHO }, /* 118 */
  { 21, "D2^6  ", "C 2 2           ", "C 2 2 2                        ", "C 2 2 2            ", "C222      ", "     ", SpaceGroups::ORTHO }, /* 119 */
  { 21, "D2^6  ", "A 2 2           ", "A 2 2 2                        ", "A 2 2 2            ", "A222      ", "cab  ", SpaceGroups::ORTHO }, /* 120 */
  { 21, "D2^6  ", "B 2 2           ", "B 2 2 2                        ", "B 2 2 2            ", "B222      ", "bca  ", SpaceGroups::ORTHO }, /* 121 */
  { 22, "D2^7  ", "F 2 2           ", "F 2 2 2                        ", "F 2 2 2            ", "F222      ", "     ", SpaceGroups::ORTHO }, /* 122 */
  { 23, "D2^8  ", "I 2 2           ", "I 2 2 2                        ", "I 2 2 2            ", "I222      ", "     ", SpaceGroups::ORTHO }, /* 123 */
  { 24, "D2^9  ", "I 2b 2c         ", "I 2_1 2_1 2_1                  ", "I 2_1 2_1 2_1      ", "I2_12_12_1", "     ", SpaceGroups::ORTHO }, /* 124 */
  { 25, "C2v^1 ", "P 2 -2          ", "P m m 2                        ", "P m m 2            ", "Pmm2      ", "     ", SpaceGroups::ORTHO }, /* 125 */
  { 25, "C2v^1 ", "P -2 2          ", "P 2 m m                        ", "P 2 m m            ", "P2mm      ", "cab  ", SpaceGroups::ORTHO }, /* 126 */
  { 25, "C2v^1 ", "P -2 -2         ", "P m 2 m                        ", "P m 2 m            ", "Pm2m      ", "bca  ", SpaceGroups::ORTHO }, /* 127 */
  { 26, "C2v^2 ", "P 2c -2         ", "P m c 2_1                      ", "P m c 2_1          ", "Pmc2_1    ", "     ", SpaceGroups::ORTHO }, /* 128 */
  { 26, "C2v^2 ", "P 2c -2c        ", "P c m 2_1                      ", "P c m 2_1          ", "Pcm2_1    ", "ba-c ", SpaceGroups::ORTHO }, /* 129 */
  { 26, "C2v^2 ", "P -2a 2a        ", "P 2_1 m a                      ", "P 2_1 m a          ", "P2_1ma    ", "cab  ", SpaceGroups::ORTHO }, /* 130 */
  { 26, "C2v^2 ", "P -2 2a         ", "P 2_1 a m                      ", "P 2_1 a m          ", "P2_1am    ", "-cba ", SpaceGroups::ORTHO }, /* 131 */
  { 26, "C2v^2 ", "P -2 -2b        ", "P b 2_1 m                      ", "P b 2_1 m          ", "Pb2_1m    ", "bca  ", SpaceGroups::ORTHO }, /* 132 */
  { 26, "C2v^2 ", "P -2b -2        ", "P m 2_1 b                      ", "P m 2_1 b          ", "Pm2_1b    ", "a-cb ", SpaceGroups::ORTHO }, /* 133 */
  { 27, "C2v^3 ", "P 2 -2c         ", "P c c 2                        ", "P c c 2            ", "Pcc2      ", "     ", SpaceGroups::ORTHO }, /* 134 */
  { 27, "C2v^3 ", "P -2a 2         ", "P 2 a a                        ", "P 2 a a            ", "P2aa      ", "cab  ", SpaceGroups::ORTHO }, /* 135 */
  { 27, "C2v^3 ", "P -2b -2b       ", "P b 2 b                        ", "P b 2 b            ", "Pb2b      ", "bca  ", SpaceGroups::ORTHO }, /* 136 */
  { 28, "C2v^4 ", "P 2 -2a         ", "P m a 2                        ", "P m a 2            ", "Pma2      ", "     ", SpaceGroups::ORTHO }, /* 137 */
  { 28, "C2v^4 ", "P 2 -2b         ", "P b m 2                        ", "P b m 2            ", "Pbm2      ", "ba-c ", SpaceGroups::ORTHO }, /* 138 */
  { 28, "C2v^4 ", "P -2b 2         ", "P 2 m b                        ", "P 2 m b            ", "P2mb      ", "cab  ", SpaceGroups::ORTHO }, /* 139 */
  { 28, "C2v^4 ", "P -2c 2         ", "P 2 c m                        ", "P 2 c m            ", "P2cm      ", "-cba ", SpaceGroups::ORTHO }, /* 140 */
  { 28, "C2v^4 ", "P -2c -2c       ", "P c 2 m                        ", "P c 2 m            ", "Pc2m      ", "bca  ", SpaceGroups::ORTHO }, /* 141 */
  { 28, "C2v^4 ", "P -2a -2a       ", "P m 2 a                        ", "P m 2 a            ", "Pm2a      ", "a-cb ", SpaceGroups::ORTHO }, /* 142 */
  { 29, "C2v^5 ", "P 2c -2ac       ", "P c a 2_1                      ", "P c a 2_1          ", "Pca2_1    ", "     ", SpaceGroups::ORTHO }, /* 143 */
  { 29, "C2v^5 ", "P 2c -2b        ", "P b c 2_1                      ", "P b c 2_1          ", "Pbc2_1    ", "ba-c ", SpaceGroups::ORTHO }, /* 144 */
  { 29, "C2v^5 ", "P -2b 2a        ", "P 2_1 a b                      ", "P 2_1 a b          ", "P2_1ab    ", "cab  ", SpaceGroups::ORTHO }, /* 145 */
  { 29, "C2v^5 ", "P -2ac 2a       ", "P 2_1 c a                      ", "P 2_1 c a          ", "P2_1ca    ", "-cba ", SpaceGroups::ORTHO }, /* 146 */
  { 29, "C2v^5 ", "P -2bc -2c      ", "P c 2_1 b                      ", "P c 2_1 b          ", "Pc2_1b    ", "bca  ", SpaceGroups::ORTHO }, /* 147 */
  { 29, "C2v^5 ", "P -2a -2ab      ", "P b 2_1 a                      ", "P b 2_1 a          ", "Pb2_1a    ", "a-cb ", SpaceGroups::ORTHO }, /* 148 */
  { 30, "C2v^6 ", "P 2 -2bc        ", "P n c 2                        ", "P n c 2            ", "Pnc2      ", "     ", SpaceGroups::ORTHO }, /* 149 */
  { 30, "C2v^6 ", "P 2 -2ac        ", "P c n 2                        ", "P c n 2            ", "Pcn2      ", "ba-c ", SpaceGroups::ORTHO }, /* 150 */
  { 30, "C2v^6 ", "P -2ac 2        ", "P 2 n a                        ", "P 2 n a            ", "P2na      ", "cab  ", SpaceGroups::ORTHO }, /* 151 */
  { 30, "C2v^6 ", "P -2ab 2        ", "P 2 a n                        ", "P 2 a n            ", "P2an      ", "-cba ", SpaceGroups::ORTHO }, /* 152 */
  { 30, "C2v^6 ", "P -2ab -2ab     ", "P b 2 n                        ", "P b 2 n            ", "Pb2n      ", "bca  ", SpaceGroups::ORTHO }, /* 153 */
  { 30, "C2v^6 ", "P -2bc -2bc     ", "P n 2 b                        ", "P n 2 b            ", "Pn2b      ", "a-cb ", SpaceGroups::ORTHO }, /* 154 */
  { 31, "C2v^7 ", "P 2ac -2        ", "P m n 2_1                      ", "P m n 2_1          ", "Pmn2_1    ", "     ", SpaceGroups::ORTHO }, /* 155 */
  { 31, "C2v^7 ", "P 2bc -2bc      ", "P n m 2_1                      ", "P n m 2_1          ", "Pnm2_1    ", "ba-c ", SpaceGroups::ORTHO }, /* 156 */
  { 31, "C2v^7 ", "P -2ab 2ab      ", "P 2_1 m n                      ", "P 2_1 m n          ", "P2_1mn    ", "cab  ", SpaceGroups::ORTHO }, /* 157 */
  { 31, "C2v^7 ", "P -2 2ac        ", "P 2_1 n m                      ", "P 2_1 n m          ", "P2_1nm    ", "-cba ", SpaceGroups::ORTHO }, /* 158 */
  { 31, "C2v^7 ", "P -2 -2bc       ", "P n 2_1 m                      ", "P n 2_1 m          ", "Pn2_1m    ", "bca  ", SpaceGroups::ORTHO }, /* 159 */
  { 31, "C2v^7 ", "P -2ab -2       ", "P m 2_1 n                      ", "P m 2_1 n          ", "Pm2_1n    ", "a-cb ", SpaceGroups::ORTHO }, /* 160 */
  { 32, "C2v^8 ", "P 2 -2ab        ", "P b a 2                        ", "P b a 2            ", "Pba2      ", "     ", SpaceGroups::ORTHO }, /* 161 */
  { 32, "C2v^8 ", "P -2bc 2        ", "P 2 c b                        ", "P 2 c b            ", "P2cb      ", "cab  ", SpaceGroups::ORTHO }, /* 162 */
  { 32, "C2v^8 ", "P -2ac -2ac     ", "P c 2 a                        ", "P c 2 a            ", "Pc2a      ", "bca  ", SpaceGroups::ORTHO }, /* 163 */
  { 33, "C2v^9 ", "P 2c -2n        ", "P n a 2_1                      ", "P n a 2_1          ", "Pna2_1    ", "     ", SpaceGroups::ORTHO }, /* 164 */
  { 33, "C2v^9 ", "P 2c -2ab       ", "P b n 2_1                      ", "P b n 2_1          ", "Pbn2_1    ", "ba-c ", SpaceGroups::ORTHO }, /* 165 */
  { 33, "C2v^9 ", "P -2bc 2a       ", "P 2_1 n b                      ", "P 2_1 n b          ", "P2_1nb    ", "cab  ", SpaceGroups::ORTHO }, /* 166 */
  { 33, "C2v^9 ", "P -2n 2a        ", "P 2_1 c n                      ", "P 2_1 c n          ", "P2_1cn    ", "-cba ", SpaceGroups::ORTHO }, /* 167 */
  { 33, "C2v^9 ", "P -2n -2ac      ", "P c 2_1 n                      ", "P c 2_1 n          ", "Pc2_1n    ", "bca  ", SpaceGroups::ORTHO }, /* 168 */
  { 33, "C2v^9 ", "P -2ac -2n      ", "P n 2_1 a                      ", "P n 2_1 a          ", "Pn2_1a    ", "a-cb ", SpaceGroups::ORTHO }, /* 169 */
  { 34, "C2v^10", "P 2 -2n         ", "P n n 2                        ", "P n n 2            ", "Pnn2      ", "     ", SpaceGroups::ORTHO }, /* 170 */
  { 34, "C2v^10", "P -2n 2         ", "P 2 n n                        ", "P 2 n n            ", "P2nn      ", "cab  ", SpaceGroups::ORTHO }, /* 171 */
  { 34, "C2v^10", "P -2n -2n       ", "P n 2 n                        ", "P n 2 n            ", "Pn2n      ", "bca  ", SpaceGroups::ORTHO }, /* 172 */
  { 35, "C2v^11", "C 2 -2          ", "C m m 2                        ", "C m m 2            ", "Cmm2      ", "     ", SpaceGroups::ORTHO }, /* 173 */
  { 35, "C2v^11", "A -2 2          ", "A 2 m m                        ", "A 2 m m            ", "A2mm      ", "cab  ", SpaceGroups::ORTHO }, /* 174 */
  { 35, "C2v^11", "B -2 -2         ", "B m 2 m                        ", "B m 2 m            ", "Bm2m      ", "bca  ", SpaceGroups::ORTHO }, /* 175 */
  { 36, "C2v^12", "C 2c -2         ", "C m c 2_1                      ", "C m c 2_1          ", "Cmc2_1    ", "     ", SpaceGroups::ORTHO }, /* 176 */
  { 36, "C2v^12", "C 2c -2c        ", "C c m 2_1                      ", "C c m 2_1          ", "Ccm2_1    ", "ba-c ", SpaceGroups::ORTHO }, /* 177 */
  { 36, "C2v^12", "A -2a 2a        ", "A 2_1 m a                      ", "A 2_1 m a          ", "A2_1ma    ", "cab  ", SpaceGroups::ORTHO }, /* 178 */
  { 36, "C2v^12", "A -2 2a         ", "A 2_1 a m                      ", "A 2_1 a m          ", "A2_1am    ", "-cba ", SpaceGroups::ORTHO }, /* 179 */
  { 36, "C2v^12", "B -2 -2b        ", "B b 2_1 m                      ", "B b 2_1 m          ", "Bb2_1m    ", "bca  ", SpaceGroups::ORTHO }, /* 180 */
  { 36, "C2v^12", "B -2b -2        ", "B m 2_1 b                      ", "B m 2_1 b          ", "Bm2_1b    ", "a-cb ", SpaceGroups::ORTHO }, /* 181 */
  { 37, "C2v^13", "C 2 -2c         ", "C c c 2                        ", "C c c 2            ", "Ccc2      ", "     ", SpaceGroups::ORTHO }, /* 182 */
  { 37, "C2v^13", "A -2a 2         ", "A 2 a a                        ", "A 2 a a            ", "A2aa      ", "cab  ", SpaceGroups::ORTHO }, /* 183 */
  { 37, "C2v^13", "B -2b -2b       ", "B b 2 b                        ", "B b 2 b            ", "Bb2b      ", "bca  ", SpaceGroups::ORTHO }, /* 184 */
  { 38, "C2v^14", "A 2 -2          ", "A m m 2                        ", "A m m 2            ", "Amm2      ", "     ", SpaceGroups::ORTHO }, /* 185 */
  { 38, "C2v^14", "B 2 -2          ", "B m m 2                        ", "B m m 2            ", "Bmm2      ", "ba-c ", SpaceGroups::ORTHO }, /* 186 */
  { 38, "C2v^14", "B -2 2          ", "B 2 m m                        ", "B 2 m m            ", "B2mm      ", "cab  ", SpaceGroups::ORTHO }, /* 187 */
  { 38, "C2v^14", "C -2 2          ", "C 2 m m                        ", "C 2 m m            ", "C2mm      ", "-cba ", SpaceGroups::ORTHO }, /* 188 */
  { 38, "C2v^14", "C -2 -2         ", "C m 2 m                        ", "C m 2 m            ", "Cm2m      ", "bca  ", SpaceGroups::ORTHO }, /* 189 */
  { 38, "C2v^14", "A -2 -2         ", "A m 2 m                        ", "A m 2 m            ", "Am2m      ", "a-cb ", SpaceGroups::ORTHO }, /* 190 */
  { 39, "C2v^15", "A 2 -2c         ", "A e m 2                        ", "A e m 2            ", "Aem2      ", "     ", SpaceGroups::ORTHO }, /* 191 */
  { 39, "C2v^15", "B 2 -2c         ", "B m e 2                        ", "B m e 2            ", "Bme2      ", "ba-c ", SpaceGroups::ORTHO }, /* 192 */
  { 39, "C2v^15", "B -2c 2         ", "B 2 e m                        ", "B 2 e m            ", "B2em      ", "cab  ", SpaceGroups::ORTHO }, /* 193 */
  { 39, "C2v^15", "C -2b 2         ", "C 2 m e                        ", "C 2 m e            ", "C2me      ", "-cba ", SpaceGroups::ORTHO }, /* 194 */
  { 39, "C2v^15", "C -2b -2b       ", "C m 2 e                        ", "C m 2 e            ", "Cm2e      ", "bca  ", SpaceGroups::ORTHO }, /* 195 */
  { 39, "C2v^15", "A -2c -2c       ", "A e 2 m                        ", "A e 2 m            ", "Ae2m      ", "a-cb ", SpaceGroups::ORTHO }, /* 196 */
  { 40, "C2v^16", "A 2 -2a         ", "A m a 2                        ", "A m a 2            ", "Ama2      ", "     ", SpaceGroups::ORTHO }, /* 197 */
  { 40, "C2v^16", "B 2 -2b         ", "B b m 2                        ", "B b m 2            ", "Bbm2      ", "ba-c ", SpaceGroups::ORTHO }, /* 198 */
  { 40, "C2v^16", "B -2b 2         ", "B 2 m b                        ", "B 2 m b            ", "B2mb      ", "cab  ", SpaceGroups::ORTHO }, /* 199 */
  { 40, "C2v^16", "C -2c 2         ", "C 2 c m                        ", "C 2 c m            ", "C2cm      ", "-cba ", SpaceGroups::ORTHO }, /* 200 */
  { 40, "C2v^16", "C -2c -2c       ", "C c 2 m                        ", "C c 2 m            ", "Cc2m      ", "bca  ", SpaceGroups::ORTHO }, /* 201 */
  { 40, "C2v^16", "A -2a -2a       ", "A m 2 a                        ", "A m 2 a            ", "Am2a      ", "a-cb ", SpaceGroups::ORTHO }, /* 202 */
  { 41, "C2v^17", "A 2 -2ac        ", "A e a 2                        ", "A e a 2            ", "Aea2      ", "     ", SpaceGroups::ORTHO }, /* 203 */
  { 41, "C2v^17", "B 2 -2bc        ", "B b e 2                        ", "B b e 2            ", "Bbe2      ", "ba-c ", SpaceGroups::ORTHO }, /* 204 */
  { 41, "C2v^17", "B -2bc 2        ", "B 2 e b                        ", "B 2 e b            ", "B2eb      ", "cab  ", SpaceGroups::ORTHO }, /* 205 */
  { 41, "C2v^17", "C -2bc 2        ", "C 2 c e                        ", "C 2 c e            ", "C2ce      ", "-cba ", SpaceGroups::ORTHO }, /* 206 */
  { 41, "C2v^17", "C -2bc -2bc     ", "C c 2 e                        ", "C c 2 e            ", "Cc2e      ", "bca  ", SpaceGroups::ORTHO }, /* 207 */
  { 41, "C2v^17", "A -2ac -2ac     ", "A e 2 a                        ", "A e 2 a            ", "Ae2a      ", "a-cb ", SpaceGroups::ORTHO }, /* 208 */
  { 42, "C2v^18", "F 2 -2          ", "F m m 2                        ", "F m m 2            ", "Fmm2      ", "     ", SpaceGroups::ORTHO }, /* 209 */
  { 42, "C2v^18", "F -2 2          ", "F 2 m m                        ", "F 2 m m            ", "F2mm      ", "cab  ", SpaceGroups::ORTHO }, /* 210 */
  { 42, "C2v^18", "F -2 -2         ", "F m 2 m                        ", "F m 2 m            ", "Fm2m      ", "bca  ", SpaceGroups::ORTHO }, /* 211 */
  { 43, "C2v^19", "F 2 -2d         ", "F d d 2                        ", "F d d 2            ", "Fdd2      ", "     ", SpaceGroups::ORTHO }, /* 212 */
  { 43, "C2v^19", "F -2d 2         ", "F 2 d d                        ", "F 2 d d            ", "F2dd      ", "cab  ", SpaceGroups::ORTHO }, /* 213 */
  { 43, "C2v^19", "F -2d -2d       ", "F d 2 d                        ", "F d 2 d            ", "Fd2d      ", "bca  ", SpaceGroups::ORTHO }, /* 214 */
  { 44, "C2v^20", "I 2 -2          ", "I m m 2                        ", "I m m 2            ", "Imm2      ", "     ", SpaceGroups::ORTHO }, /* 215 */
  { 44, "C2v^20", "I -2 2          ", "I 2 m m                        ", "I 2 m m            ", "I2mm      ", "cab  ", SpaceGroups::ORTHO }, /* 216 */
  { 44, "C2v^20", "I -2 -2         ", "I m 2 m                        ", "I m 2 m            ", "Im2m      ", "bca  ", SpaceGroups::ORTHO }, /* 217 */
  { 45, "C2v^21", "I 2 -2c         ", "I b a 2                        ", "I b a 2            ", "Iba2      ", "     ", SpaceGroups::ORTHO }, /* 218 */
  { 45, "C2v^21", "I -2a 2         ", "I 2 c b                        ", "I 2 c b            ", "I2cb      ", "cab  ", SpaceGroups::ORTHO }, /* 219 */
  { 45, "C2v^21", "I -2b -2b       ", "I c 2 a                        ", "I c 2 a            ", "Ic2a      ", "bca  ", SpaceGroups::ORTHO }, /* 220 */
  { 46, "C2v^22", "I 2 -2a         ", "I m a 2                        ", "I m a 2            ", "Ima2      ", "     ", SpaceGroups::ORTHO }, /* 221 */
  { 46, "C2v^22", "I 2 -2b         ", "I b m 2                        ", "I b m 2            ", "Ibm2      ", "ba-c ", SpaceGroups::ORTHO }, /* 222 */
  { 46, "C2v^22", "I -2b 2         ", "I 2 m b                        ", "I 2 m b            ", "I2mb      ", "cab  ", SpaceGroups::ORTHO }, /* 223 */
  { 46, "C2v^22", "I -2c 2         ", "I 2 c m                        ", "I 2 c m            ", "I2cm      ", "-cba ", SpaceGroups::ORTHO }, /* 224 */
  { 46, "C2v^22", "I -2c -2c       ", "I c 2 m                        ", "I c 2 m            ", "Ic2m      ", "bca  ", SpaceGroups::ORTHO }, /* 225 */
  { 46, "C2v^22", "I -2a -2a       ", "I m 2 a                        ", "I m 2 a            ", "Im2a      ", "a-cb ", SpaceGroups::ORTHO }, /* 226 */
  { 47, "D2h^1 ", "-P 2 2          ", "P m m m                        ", "P 2/m 2/m 2/m      ", "Pmmm      ", "     ", SpaceGroups::ORTHO }, /* 227 */
  { 48, "D2h^2 ", "P 2 2 -1n       ", "P n n n                        ", "P 2/n 2/n 2/n      ", "Pnnn      ", "1    ", SpaceGroups::ORTHO }, /* 228 */
  { 48, "D2h^2 ", "-P 2ab 2bc      ", "P n n n                        ", "P 2/n 2/n 2/n      ", "Pnnn      ", "2    ", SpaceGroups::ORTHO }, /* 229 */
  { 49, "D2h^3 ", "-P 2 2c         ", "P c c m                        ", "P 2/c 2/c 2/m      ", "Pccm      ", "     ", SpaceGroups::ORTHO }, /* 230 */
  { 49, "D2h^3 ", "-P 2a 2         ", "P m a a                        ", "P 2/m 2/a 2/a      ", "Pmaa      ", "cab  ", SpaceGroups::ORTHO }, /* 231 */
  { 49, "D2h^3 ", "-P 2b 2b        ", "P b m b                        ", "P 2/b 2/m 2/b      ", "Pbmb      ", "bca  ", SpaceGroups::ORTHO }, /* 232 */
  { 50, "D2h^4 ", "P 2 2 -1ab      ", "P b a n                        ", "P 2/b 2/a 2/n      ", "Pban      ", "1    ", SpaceGroups::ORTHO }, /* 233 */
  { 50, "D2h^4 ", "-P 2ab 2b       ", "P b a n                        ", "P 2/b 2/a 2/n      ", "Pban      ", "2    ", SpaceGroups::ORTHO }, /* 234 */
  { 50, "D2h^4 ", "P 2 2 -1bc      ", "P n c b                        ", "P 2/n 2/c 2/b      ", "Pncb      ", "1cab ", SpaceGroups::ORTHO }, /* 235 */
  { 50, "D2h^4 ", "-P 2b 2bc       ", "P n c b                        ", "P 2/n 2/c 2/b      ", "Pncb      ", "2cab ", SpaceGroups::ORTHO }, /* 236 */
  { 50, "D2h^4 ", "P 2 2 -1ac      ", "P c n a                        ", "P 2/c 2/n 2/a      ", "Pcna      ", "1bca ", SpaceGroups::ORTHO }, /* 237 */
  { 50, "D2h^4 ", "-P 2a 2c        ", "P c n a                        ", "P 2/c 2/n 2/a      ", "Pcna      ", "2bca ", SpaceGroups::ORTHO }, /* 238 */
  { 51, "D2h^5 ", "-P 2a 2a        ", "P m m a                        ", "P 2_1/m 2/m 2/a    ", "Pmma      ", "     ", SpaceGroups::ORTHO }, /* 239 */
  { 51, "D2h^5 ", "-P 2b 2         ", "P m m b                        ", "P 2/m 2_1/m 2/b    ", "Pmmb      ", "ba-c ", SpaceGroups::ORTHO }, /* 240 */
  { 51, "D2h^5 ", "-P 2 2b         ", "P b m m                        ", "P 2/b 2_1/m 2/m    ", "Pbmm      ", "cab  ", SpaceGroups::ORTHO }, /* 241 */
  { 51, "D2h^5 ", "-P 2c 2c        ", "P c m m                        ", "P 2/c 2/m 2_1/m    ", "Pcmm      ", "-cba ", SpaceGroups::ORTHO }, /* 242 */
  { 51, "D2h^5 ", "-P 2c 2         ", "P m c m                        ", "P 2/m 2/c 2_1/m    ", "Pmcm      ", "bca  ", SpaceGroups::ORTHO }, /* 243 */
  { 51, "D2h^5 ", "-P 2 2a         ", "P m a m                        ", "P 2_1/m 2/a 2/m    ", "Pmam      ", "a-cb ", SpaceGroups::ORTHO }, /* 244 */
  { 52, "D2h^6 ", "-P 2a 2bc       ", "P n n a                        ", "P 2/n 2_1/n 2/a    ", "Pnna      ", "     ", SpaceGroups::ORTHO }, /* 245 */
  { 52, "D2h^6 ", "-P 2b 2n        ", "P n n b                        ", "P 2_1/n 2/n 2/b    ", "Pnnb      ", "ba-c ", SpaceGroups::ORTHO }, /* 246 */
  { 52, "D2h^6 ", "-P 2n 2b        ", "P b n n                        ", "P 2/b 2/n 2_1/n    ", "Pbnn      ", "cab  ", SpaceGroups::ORTHO }, /* 247 */
  { 52, "D2h^6 ", "-P 2ab 2c       ", "P c n n                        ", "P 2/c 2_1/n 2/n    ", "Pcnn      ", "-cba ", SpaceGroups::ORTHO }, /* 248 */
  { 52, "D2h^6 ", "-P 2ab 2n       ", "P n c n                        ", "P 2_1/n 2/c 2/n    ", "Pncn      ", "bca  ", SpaceGroups::ORTHO }, /* 249 */
  { 52, "D2h^6 ", "-P 2n 2bc       ", "P n a n                        ", "P 2/n 2/a 2_1/n    ", "Pnan      ", "a-cb ", SpaceGroups::ORTHO }, /* 250 */
  { 53, "D2h^7 ", "-P 2ac 2        ", "P m n a                        ", "P 2/m 2/n 2_1/a    ", "Pmna      ", "     ", SpaceGroups::ORTHO }, /* 251 */
  { 53, "D2h^7 ", "-P 2bc 2bc      ", "P n m b                        ", "P 2/n 2/m 2_1/b    ", "Pnmb      ", "ba-c ", SpaceGroups::ORTHO }, /* 252 */
  { 53, "D2h^7 ", "-P 2ab 2ab      ", "P b m n                        ", "P 2_1/b 2/m 2/n    ", "Pbmn      ", "cab  ", SpaceGroups::ORTHO }, /* 253 */
  { 53, "D2h^7 ", "-P 2 2ac        ", "P c n m                        ", "P 2_1/c 2/n 2/m    ", "Pcnm      ", "-cba ", SpaceGroups::ORTHO }, /* 254 */
  { 53, "D2h^7 ", "-P 2 2bc        ", "P n c m                        ", "P 2/n 2_1/c 2/m    ", "Pncm      ", "bca  ", SpaceGroups::ORTHO }, /* 255 */
  { 53, "D2h^7 ", "-P 2ab 2        ", "P m a n                        ", "P 2/m 2_1/a 2/n    ", "Pman      ", "a-cb ", SpaceGroups::ORTHO }, /* 256 */
  { 54, "D2h^8 ", "-P 2a 2ac       ", "P c c a                        ", "P 2_1/c 2/c 2/a    ", "Pcca      ", "     ", SpaceGroups::ORTHO }, /* 257 */
  { 54, "D2h^8 ", "-P 2b 2c        ", "P c c b                        ", "P 2/c 2_1/c 2/b    ", "Pccb      ", "ba-c ", SpaceGroups::ORTHO }, /* 258 */
  { 54, "D2h^8 ", "-P 2a 2b        ", "P b a a                        ", "P 2/b 2_1/a 2/a    ", "Pbaa      ", "cab  ", SpaceGroups::ORTHO }, /* 259 */
  { 54, "D2h^8 ", "-P 2ac 2c       ", "P c a a                        ", "P 2/c 2/a 2_1/a    ", "Pcaa      ", "-cba ", SpaceGroups::ORTHO }, /* 260 */
  { 54, "D2h^8 ", "-P 2bc 2b       ", "P b c b                        ", "P 2/b 2/c 2_1/b    ", "Pbcb      ", "bca  ", SpaceGroups::ORTHO }, /* 261 */
  { 54, "D2h^8 ", "-P 2b 2ab       ", "P b a b                        ", "P 2_1/b 2/a 2/b    ", "Pbab      ", "a-cb ", SpaceGroups::ORTHO }, /* 262 */
  { 55, "D2h^9 ", "-P 2 2ab        ", "P b a m                        ", "P 2_1/b 2_1/a 2/m  ", "Pbam      ", "     ", SpaceGroups::ORTHO }, /* 263 */
  { 55, "D2h^9 ", "-P 2bc 2        ", "P m c b                        ", "P 2/m 2_1/c 2_1/b  ", "Pmcb      ", "cab  ", SpaceGroups::ORTHO }, /* 264 */
  { 55, "D2h^9 ", "-P 2ac 2ac      ", "P c m a                        ", "P 2_1/c 2/m 2_1/a  ", "Pcma      ", "bca  ", SpaceGroups::ORTHO }, /* 265 */
  { 56, "D2h^10", "-P 2ab 2ac      ", "P c c n                        ", "P 2_1/c 2_1/c 2/n  ", "Pccn      ", "     ", SpaceGroups::ORTHO }, /* 266 */
  { 56, "D2h^10", "-P 2ac 2bc      ", "P n a a                        ", "P 2/n 2_1/a 2_1/a  ", "Pnaa      ", "cab  ", SpaceGroups::ORTHO }, /* 267 */
  { 56, "D2h^10", "-P 2bc 2ab      ", "P b n b                        ", "P 2_1/b 2/n 2_1/b  ", "Pbnb      ", "bca  ", SpaceGroups::ORTHO }, /* 268 */
  { 57, "D2h^11", "-P 2c 2b        ", "P b c m                        ", "P 2/b 2_1/c 2_1/m  ", "Pbcm      ", "     ", SpaceGroups::ORTHO }, /* 269 */
  { 57, "D2h^11", "-P 2c 2ac       ", "P c a m                        ", "P 2_1/c 2/a 2_1/m  ", "Pcam      ", "ba-c ", SpaceGroups::ORTHO }, /* 270 */
  { 57, "D2h^11", "-P 2ac 2a       ", "P m c a                        ", "P 2_1/m 2/c 2_1/a  ", "Pmca      ", "cab  ", SpaceGroups::ORTHO }, /* 271 */
  { 57, "D2h^11", "-P 2b 2a        ", "P m a b                        ", "P 2_1/m 2_1/a 2/b  ", "Pmab      ", "-cba ", SpaceGroups::ORTHO }, /* 272 */
  { 57, "D2h^11", "-P 2a 2ab       ", "P b m a                        ", "P 2_1/b 2_1/m 2/a  ", "Pbma      ", "bca  ", SpaceGroups::ORTHO }, /* 273 */
  { 57, "D2h^11", "-P 2bc 2c       ", "P c m b                        ", "P 2/c 2_1/m 2_1/b  ", "Pcmb      ", "a-cb ", SpaceGroups::ORTHO }, /* 274 */
  { 58, "D2h^12", "-P 2 2n         ", "P n n m                        ", "P 2_1/n 2_1/n 2/m  ", "Pnnm      ", "     ", SpaceGroups::ORTHO }, /* 275 */
  { 58, "D2h^12", "-P 2n 2         ", "P m n n                        ", "P 2/m 2_1/n 2_1/n  ", "Pmnn      ", "cab  ", SpaceGroups::ORTHO }, /* 276 */
  { 58, "D2h^12", "-P 2n 2n        ", "P n m n                        ", "P 2_1/n 2/m 2_1/n  ", "Pnmn      ", "bca  ", SpaceGroups::ORTHO }, /* 277 */
  { 59, "D2h^13", "P 2 2ab -1ab    ", "P m m n                        ", "P 2_1/m 2_1/m 2/n  ", "Pmmn      ", "1    ", SpaceGroups::ORTHO }, /* 278 */
  { 59, "D2h^13", "-P 2ab 2a       ", "P m m n                        ", "P 2_1/m 2_1/m 2/n  ", "Pmmn      ", "2    ", SpaceGroups::ORTHO }, /* 279 */
  { 59, "D2h^13", "P 2bc 2 -1bc    ", "P n m m                        ", "P 2/n 2_1/m 2_1/m  ", "Pnmm      ", "1cab ", SpaceGroups::ORTHO }, /* 280 */
  { 59, "D2h^13", "-P 2c 2bc       ", "P n m m                        ", "P 2/n 2_1/m 2_1/m  ", "Pnmm      ", "2cab ", SpaceGroups::ORTHO }, /* 281 */
  { 59, "D2h^13", "P 2ac 2ac -1ac  ", "P m n m                        ", "P 2_1/m 2/n 2_1/m  ", "Pmnm      ", "1bca ", SpaceGroups::ORTHO }, /* 282 */
  { 59, "D2h^13", "-P 2c 2a        ", "P m n m                        ", "P 2_1/m 2/n 2_1/m  ", "Pmnm      ", "2bca ", SpaceGroups::ORTHO }, /* 283 */
  { 60, "D2h^14", "-P 2n 2ab       ", "P b c n                        ", "P 2_1/b 2/c 2_1/n  ", "Pbcn      ", "     ", SpaceGroups::ORTHO }, /* 284 */
  { 60, "D2h^14", "-P 2n 2c        ", "P c a n                        ", "P 2/c 2_1/a 2_1/n  ", "Pcan      ", "ba-c ", SpaceGroups::ORTHO }, /* 285 */
  { 60, "D2h^14", "-P 2a 2n        ", "P n c a                        ", "P 2_1/n 2_1/c 2/a  ", "Pnca      ", "cab  ", SpaceGroups::ORTHO }, /* 286 */
  { 60, "D2h^14", "-P 2bc 2n       ", "P n a b                        ", "P 2_1/n 2/a 2_1/b  ", "Pnab      ", "-cba ", SpaceGroups::ORTHO }, /* 287 */
  { 60, "D2h^14", "-P 2ac 2b       ", "P b n a                        ", "P 2/b 2_1/n 2_1/a  ", "Pbna      ", "bca  ", SpaceGroups::ORTHO }, /* 288 */
  { 60, "D2h^14", "-P 2b 2ac       ", "P c n b                        ", "P 2_1/c 2_1/n 2/b  ", "Pcnb      ", "a-cb ", SpaceGroups::ORTHO }, /* 289 */
  { 61, "D2h^15", "-P 2ac 2ab      ", "P b c a                        ", "P 2_1/b 2_1/c 2_1/a", "Pbca      ", "     ", SpaceGroups::ORTHO }, /* 290 */
  { 61, "D2h^15", "-P 2bc 2ac      ", "P c a b                        ", "P 2_1/c 2_1/a 2_1/b", "Pcab      ", "ba-c ", SpaceGroups::ORTHO }, /* 291 */
  { 62, "D2h^16", "-P 2ac 2n       ", "P n m a                        ", "P 2_1/n 2_1/m 2_1/a", "Pnma      ", "     ", SpaceGroups::ORTHO }, /* 292 */
  { 62, "D2h^16", "-P 2bc 2a       ", "P m n b                        ", "P 2_1/m 2_1/n 2_1/b", "Pmnb      ", "ba-c ", SpaceGroups::ORTHO }, /* 293 */
  { 62, "D2h^16", "-P 2c 2ab       ", "P b n m                        ", "P 2_1/b 2_1/n 2_1/m", "Pbnm      ", "cab  ", SpaceGroups::ORTHO }, /* 294 */
  { 62, "D2h^16", "-P 2n 2ac       ", "P c m n                        ", "P 2_1/c 2_1/m 2_1/n", "Pcmn      ", "-cba ", SpaceGroups::ORTHO }, /* 295 */
  { 62, "D2h^16", "-P 2n 2a        ", "P m c n                        ", "P 2_1/m 2_1/c 2_1/n", "Pmcn      ", "bca  ", SpaceGroups::ORTHO }, /* 296 */
  { 62, "D2h^16", "-P 2c 2n        ", "P n a m                        ", "P 2_1/n 2_1/a 2_1/m", "Pnam      ", "a-cb ", SpaceGroups::ORTHO }, /* 297 */
  { 63, "D2h^17", "-C 2c 2         ", "C m c m                        ", "C 2/m 2/c 2_1/m    ", "Cmcm      ", "     ", SpaceGroups::ORTHO }, /* 298 */
  { 63, "D2h^17", "-C 2c 2c        ", "C c m m                        ", "C 2/c 2/m 2_1/m    ", "Ccmm      ", "ba-c ", SpaceGroups::ORTHO }, /* 299 */
  { 63, "D2h^17", "-A 2a 2a        ", "A m m a                        ", "A 2_1/m 2/m 2/a    ", "Amma      ", "cab  ", SpaceGroups::ORTHO }, /* 300 */
  { 63, "D2h^17", "-A 2 2a         ", "A m a m                        ", "A 2_1/m 2/a 2/m    ", "Amam      ", "-cba ", SpaceGroups::ORTHO }, /* 301 */
  { 63, "D2h^17", "-B 2 2b         ", "B b m m                        ", "B 2/b 2_1/m 2/m    ", "Bbmm      ", "bca  ", SpaceGroups::ORTHO }, /* 302 */
  { 63, "D2h^17", "-B 2b 2         ", "B m m b                        ", "B 2/m 2_1/m 2/b    ", "Bmmb      ", "a-cb ", SpaceGroups::ORTHO }, /* 303 */
  { 64, "D2h^18", "-C 2bc 2        ", "C m c e                        ", "C 2/m 2/c 2_1/e    ", "Cmce      ", "     ", SpaceGroups::ORTHO }, /* 304 */
  { 64, "D2h^18", "-C 2bc 2bc      ", "C c m e                        ", "C 2/c 2/m 2_1/e    ", "Ccme      ", "ba-c ", SpaceGroups::ORTHO }, /* 305 */
  { 64, "D2h^18", "-A 2ac 2ac      ", "A e m a                        ", "A 2_1/e 2/m 2/a    ", "Aema      ", "cab  ", SpaceGroups::ORTHO }, /* 306 */
  { 64, "D2h^18", "-A 2 2ac        ", "A e a m                        ", "A 2_1/e 2/a 2/m    ", "Aeam      ", "-cba ", SpaceGroups::ORTHO }, /* 307 */
  { 64, "D2h^18", "-B 2 2bc        ", "B b e m                        ", "B 2/b 2_1/e 2/m    ", "Bbem      ", "bca  ", SpaceGroups::ORTHO }, /* 308 */
  { 64, "D2h^18", "-B 2bc 2        ", "B m e b                        ", "B 2/m 2_1/e 2/b    ", "Bmeb      ", "a-cb ", SpaceGroups::ORTHO }, /* 309 */
  { 65, "D2h^19", "-C 2 2          ", "C m m m                        ", "C 2/m 2/m 2/m      ", "Cmmm      ", "     ", SpaceGroups::ORTHO }, /* 310 */
  { 65, "D2h^19", "-A 2 2          ", "A m m m                        ", "A 2/m 2/m 2/m      ", "Ammm      ", "cab  ", SpaceGroups::ORTHO }, /* 311 */
  { 65, "D2h^19", "-B 2 2          ", "B m m m                        ", "B 2/m 2/m 2/m      ", "Bmmm      ", "bca  ", SpaceGroups::ORTHO }, /* 312 */
  { 66, "D2h^20", "-C 2 2c         ", "C c c m                        ", "C 2/c 2/c 2/m      ", "Cccm      ", "     ", SpaceGroups::ORTHO }, /* 313 */
  { 66, "D2h^20", "-A 2a 2         ", "A m a a                        ", "A 2/m 2/a 2/a      ", "Amaa      ", "cab  ", SpaceGroups::ORTHO }, /* 314 */
  { 66, "D2h^20", "-B 2b 2b        ", "B b m b                        ", "B 2/b 2/m 2/b      ", "Bbmb      ", "bca  ", SpaceGroups::ORTHO }, /* 315 */
  { 67, "D2h^21", "-C 2b 2         ", "C m m e                        ", "C 2/m 2/m 2/e      ", "Cmme      ", "     ", SpaceGroups::ORTHO }, /* 316 */
  { 67, "D2h^21", "-C 2b 2b        ", "C m m e                        ", "C 2/m 2/m 2/e      ", "Cmme      ", "ba-c ", SpaceGroups::ORTHO }, /* 317 */
  { 67, "D2h^21", "-A 2c 2c        ", "A e m m                        ", "A 2/e 2/m 2/m      ", "Aemm      ", "cab  ", SpaceGroups::ORTHO }, /* 318 */
  { 67, "D2h^21", "-A 2 2c         ", "A e m m                        ", "A 2/e 2/m 2/m      ", "Aemm      ", "-cba ", SpaceGroups::ORTHO }, /* 319 */
  { 67, "D2h^21", "-B 2 2c         ", "B m e m                        ", "B 2/m 2/e 2/m      ", "Bmem      ", "bca  ", SpaceGroups::ORTHO }, /* 320 */
  { 67, "D2h^21", "-B 2c 2         ", "B m e m                        ", "B 2/m 2/e 2/m      ", "Bmem      ", "a-cb ", SpaceGroups::ORTHO }, /* 321 */
  { 68, "D2h^22", "C 2 2 -1bc      ", "C c c e                        ", "C 2/c 2/c 2/e      ", "Ccce      ", "1    ", SpaceGroups::ORTHO }, /* 322 */
  { 68, "D2h^22", "-C 2b 2bc       ", "C c c e                        ", "C 2/c 2/c 2/e      ", "Ccce      ", "2    ", SpaceGroups::ORTHO }, /* 323 */
  { 68, "D2h^22", "C 2 2 -1bc      ", "C c c e                        ", "C 2/c 2/c 2/e      ", "Ccce      ", "1ba-c", SpaceGroups::ORTHO }, /* 324 */
  { 68, "D2h^22", "-C 2b 2c        ", "C c c e                        ", "C 2/c 2/c 2/e      ", "Ccce      ", "2ba-c", SpaceGroups::ORTHO }, /* 325 */
  { 68, "D2h^22", "A 2 2 -1ac      ", "A e a a                        ", "A 2/e 2/a 2/a      ", "Aeaa      ", "1cab ", SpaceGroups::ORTHO }, /* 326 */
  { 68, "D2h^22", "-A 2a 2c        ", "A e a a                        ", "A 2/e 2/a 2/a      ", "Aeaa      ", "2cab ", SpaceGroups::ORTHO }, /* 327 */
  { 68, "D2h^22", "A 2 2 -1ac      ", "A e a a                        ", "A 2/e 2/a 2/a      ", "Aeaa      ", "1-cba", SpaceGroups::ORTHO }, /* 328 */
  { 68, "D2h^22", "-A 2ac 2c       ", "A e a a                        ", "A 2/e 2/a 2/a      ", "Aeaa      ", "2-cba", SpaceGroups::ORTHO }, /* 329 */
  { 68, "D2h^22", "B 2 2 -1bc      ", "B b e b                        ", "B 2/b 2/e 2/b      ", "Bbeb      ", "1bca ", SpaceGroups::ORTHO }, /* 330 */
  { 68, "D2h^22", "-B 2bc 2b       ", "B b c b                        ", "B 2/b 2/e 2/b      ", "Bbcb      ", "2bca ", SpaceGroups::ORTHO }, /* 331 */
  { 68, "D2h^22", "B 2 2 -1bc      ", "B b e b                        ", "B 2/b 2/e 2/b      ", "Bbeb      ", "1a-cb", SpaceGroups::ORTHO }, /* 332 */
  { 68, "D2h^22", "-B 2b 2bc       ", "B b e b                        ", "B 2/b 2/e 2/b      ", "Bbeb      ", "2a-cb", SpaceGroups::ORTHO }, /* 333 */
  { 69, "D2h^23", "-F 2 2          ", "F m m m                        ", "F 2/m 2/m 2/m      ", "Fmmm      ", "     ", SpaceGroups::ORTHO }, /* 334 */
  { 70, "D2h^24", "F 2 2 -1d       ", "F d d d                        ", "F 2/d 2/d 2/d      ", "Fddd      ", "1    ", SpaceGroups::ORTHO }, /* 335 */
  { 70, "D2h^24", "-F 2uv 2vw      ", "F d d d                        ", "F 2/d 2/d 2/d      ", "Fddd      ", "2    ", SpaceGroups::ORTHO }, /* 336 */
  { 71, "D2h^25", "-I 2 2          ", "I m m m                        ", "I 2/m 2/m 2/m      ", "Immm      ", "     ", SpaceGroups::ORTHO }, /* 337 */
  { 72, "D2h^26", "-I 2 2c         ", "I b a m                        ", "I 2/b 2/a 2/m      ", "Ibam      ", "     ", SpaceGroups::ORTHO }, /* 338 */
  { 72, "D2h^26", "-I 2a 2         ", "I m c b                        ", "I 2/m 2/c 2/b      ", "Imcb      ", "cab  ", SpaceGroups::ORTHO }, /* 339 */
  { 72, "D2h^26", "-I 2b 2b        ", "I c m a                        ", "I 2/c 2/m 2/a      ", "Icma      ", "bca  ", SpaceGroups::ORTHO }, /* 340 */
  { 73, "D2h^27", "-I 2b 2c        ", "I b c a                        ", "I 2/b 2/c 2/a      ", "Ibca      ", "     ", SpaceGroups::ORTHO }, /* 341 */
  { 73, "D2h^27", "-I 2a 2b        ", "I c a b                        ", "I 2/c 2/a 2/b      ", "Icab      ", "ba-c ", SpaceGroups::ORTHO }, /* 342 */
  { 74, "D2h^28", "-I 2b 2         ", "I m m a                        ", "I 2/m 2/m 2/a      ", "Imma      ", "     ", SpaceGroups::ORTHO }, /* 343 */
  { 74, "D2h^28", "-I 2a 2a        ", "I m m b                        ", "I 2/m 2/m 2/b      ", "Immb      ", "ba-c ", SpaceGroups::ORTHO }, /* 344 */
  { 74, "D2h^28", "-I 2c 2c        ", "I b m m                        ", "I 2/b 2/m 2/m      ", "Ibmm      ", "cab  ", SpaceGroups::ORTHO }, /* 345 */
  { 74, "D2h^28", "-I 2 2b         ", "I c m m                        ", "I 2/c 2/m 2/m      ", "Icmm      ", "-cba ", SpaceGroups::ORTHO }, /* 346 */
  { 74, "D2h^28", "-I 2 2a         ", "I m c m                        ", "I 2/m 2/c 2/m      ", "Imcm      ", "bca  ", SpaceGroups::ORTHO }, /* 347 */
  { 74, "D2h^28", "-I 2c 2         ", "I m a m                        ", "I 2/m 2/a 2/m      ", "Imam      ", "a-cb ", SpaceGroups::ORTHO }, /* 348 */
  { 75, "C4^1  ", "P 4             ", "P 4                            ", "P 4                ", "P4        ", "     ", SpaceGroups::TETRA }, /* 349 */
  { 76, "C4^2  ", "P 4w            ", "P 4_1                          ", "P 4_1              ", "P4_1      ", "     ", SpaceGroups::TETRA }, /* 350 */
  { 77, "C4^3  ", "P 4c            ", "P 4_2                          ", "P 4_2              ", "P4_2      ", "     ", SpaceGroups::TETRA }, /* 351 */
  { 78, "C4^4  ", "P 4cw           ", "P 4_3                          ", "P 4_3              ", "P4_3      ", "     ", SpaceGroups::TETRA }, /* 352 */
  { 79, "C4^5  ", "I 4             ", "I 4                            ", "I 4                ", "I4        ", "     ", SpaceGroups::TETRA }, /* 353 */
  { 80, "C4^6  ", "I 4bw           ", "I 4_1                          ", "I 4_1              ", "I4_1      ", "     ", SpaceGroups::TETRA }, /* 354 */
  { 81, "S4^1  ", "P -4            ", "P -4                           ", "P -4               ", "P-4       ", "     ", SpaceGroups::TETRA }, /* 355 */
  { 82, "S4^2  ", "I -4            ", "I -4                           ", "I -4               ", "I-4       ", "     ", SpaceGroups::TETRA }, /* 356 */
  { 83, "C4h^1 ", "-P 4            ", "P 4/m                          ", "P 4/m              ", "P4/m      ", "     ", SpaceGroups::TETRA }, /* 357 */
  { 84, "C4h^2 ", "-P 4c           ", "P 4_2/m                        ", "P 4_2/m            ", "P4_2/m    ", "     ", SpaceGroups::TETRA }, /* 358 */
  { 85, "C4h^3 ", "P 4ab -1ab      ", "P 4/n                          ", "P 4/n              ", "P4/n      ", "1    ", SpaceGroups::TETRA }, /* 359 */
  { 85, "C4h^3 ", "-P 4a           ", "P 4/n                          ", "P 4/n              ", "P4/n      ", "2    ", SpaceGroups::TETRA }, /* 360 */
  { 86, "C4h^4 ", "P 4n -1n        ", "P 4_2/n                        ", "P 4_2/n            ", "P4_2/n    ", "1    ", SpaceGroups::TETRA }, /* 361 */
  { 86, "C4h^4 ", "-P 4bc          ", "P 4_2/n                        ", "P 4_2/n            ", "P4_2/n    ", "2    ", SpaceGroups::TETRA }, /* 362 */
  { 87, "C4h^5 ", "-I 4            ", "I 4/m                          ", "I 4/m              ", "I4/m      ", "     ", SpaceGroups::TETRA }, /* 363 */
  { 88, "C4h^6 ", "I 4bw -1bw      ", "I 4_1/a                        ", "I 4_1/a            ", "I4_1/a    ", "1    ", SpaceGroups::TETRA }, /* 364 */
  { 88, "C4h^6 ", "-I 4ad          ", "I 4_1/a                        ", "I 4_1/a            ", "I4_1/a    ", "2    ", SpaceGroups::TETRA }, /* 365 */
  { 89, "D4^1  ", "P 4 2           ", "P 4 2 2                        ", "P 4 2 2            ", "P422      ", "     ", SpaceGroups::TETRA }, /* 366 */
  { 90, "D4^2  ", "P 4ab 2ab       ", "P 4 2_1 2                      ", "P 4 2_1 2          ", "P42_12    ", "     ", SpaceGroups::TETRA }, /* 367 */
  { 91, "D4^3  ", "P 4w 2c         ", "P 4_1 2 2                      ", "P 4_1 2 2          ", "P4_122    ", "     ", SpaceGroups::TETRA }, /* 368 */
  { 92, "D4^4  ", "P 4abw 2nw      ", "P 4_1 2_1 2                    ", "P 4_1 2_1 2        ", "P4_12_12  ", "     ", SpaceGroups::TETRA }, /* 369 */
  { 93, "D4^5  ", "P 4c 2          ", "P 4_2 2 2                      ", "P 4_2 2 2          ", "P4_222    ", "     ", SpaceGroups::TETRA }, /* 370 */
  { 94, "D4^6  ", "P 4n 2n         ", "P 4_2 2_1 2                    ", "P 4_2 2_1 2        ", "P4_22_12  ", "     ", SpaceGroups::TETRA }, /* 371 */
  { 95, "D4^7  ", "P 4cw 2c        ", "P 4_3 2 2                      ", "P 4_3 2 2          ", "P4_322    ", "     ", SpaceGroups::TETRA }, /* 372 */
  { 96, "D4^8  ", "P 4nw 2abw      ", "P 4_3 2_1 2                    ", "P 4_3 2_1 2        ", "P4_32_12  ", "     ", SpaceGroups::TETRA }, /* 373 */
  { 97, "D4^9  ", "I 4 2           ", "I 4 2 2                        ", "I 4 2 2            ", "I422      ", "     ", SpaceGroups::TETRA }, /* 374 */
  { 98, "D4^10 ", "I 4bw 2bw       ", "I 4_1 2 2                      ", "I 4_1 2 2          ", "I4_122    ", "     ", SpaceGroups::TETRA }, /* 375 */
  { 99, "C4v^1 ", "P 4 -2          ", "P 4 m m                        ", "P 4 m m            ", "P4mm      ", "     ", SpaceGroups::TETRA }, /* 376 */
  {100, "C4v^2 ", "P 4 -2ab        ", "P 4 b m                        ", "P 4 b m            ", "P4bm      ", "     ", SpaceGroups::TETRA }, /* 377 */
  {101, "C4v^3 ", "P 4c -2c        ", "P 4_2 c m                      ", "P 4_2 c m          ", "P4_2cm    ", "     ", SpaceGroups::TETRA }, /* 378 */
  {102, "C4v^4 ", "P 4n -2n        ", "P 4_2 n m                      ", "P 4_2 n m          ", "P4_2nm    ", "     ", SpaceGroups::TETRA }, /* 379 */
  {103, "C4v^5 ", "P 4 -2c         ", "P 4 c c                        ", "P 4 c c            ", "P4cc      ", "     ", SpaceGroups::TETRA }, /* 380 */
  {104, "C4v^6 ", "P 4 -2n         ", "P 4 n c                        ", "P 4 n c            ", "P4nc      ", "     ", SpaceGroups::TETRA }, /* 381 */
  {105, "C4v^7 ", "P 4c -2         ", "P 4_2 m c                      ", "P 4_2 m c          ", "P4_2mc    ", "     ", SpaceGroups::TETRA }, /* 382 */
  {106, "C4v^8 ", "P 4c -2ab       ", "P 4_2 b c                      ", "P 4_2 b c          ", "P4_2bc    ", "     ", SpaceGroups::TETRA }, /* 383 */
  {107, "C4v^9 ", "I 4 -2          ", "I 4 m m                        ", "I 4 m m            ", "I4mm      ", "     ", SpaceGroups::TETRA }, /* 384 */
  {108, "C4v^10", "I 4 -2c         ", "I 4 c m                        ", "I 4 c m            ", "I4cm      ", "     ", SpaceGroups::TETRA }, /* 385 */
  {109, "C4v^11", "I 4bw -2        ", "I 4_1 m d                      ", "I 4_1 m d          ", "I4_1md    ", "     ", SpaceGroups::TETRA }, /* 386 */
  {110, "C4v^12", "I 4bw -2c       ", "I 4_1 c d                      ", "I 4_1 c d          ", "I4_1cd    ", "     ", SpaceGroups::TETRA }, /* 387 */
  {111, "D2d^1 ", "P -4 2          ", "P -4 2 m                       ", "P -4 2 m           ", "P-42m     ", "     ", SpaceGroups::TETRA }, /* 388 */
  {112, "D2d^2 ", "P -4 2c         ", "P -4 2 c                       ", "P -4 2 c           ", "P-42c     ", "     ", SpaceGroups::TETRA }, /* 389 */
  {113, "D2d^3 ", "P -4 2ab        ", "P -4 2_1 m                     ", "P -4 2_1 m         ", "P-42_1m   ", "     ", SpaceGroups::TETRA }, /* 390 */
  {114, "D2d^4 ", "P -4 2n         ", "P -4 2_1 c                     ", "P -4 2_1 c         ", "P-42_1c   ", "     ", SpaceGroups::TETRA }, /* 391 */
  {115, "D2d^5 ", "P -4 -2         ", "P -4 m 2                       ", "P -4 m 2           ", "P-4m2     ", "     ", SpaceGroups::TETRA }, /* 392 */
  {116, "D2d^6 ", "P -4 -2c        ", "P -4 c 2                       ", "P -4 c 2           ", "P-4c2     ", "     ", SpaceGroups::TETRA }, /* 393 */
  {117, "D2d^7 ", "P -4 -2ab       ", "P -4 b 2                       ", "P -4 b 2           ", "P-4b2     ", "     ", SpaceGroups::TETRA }, /* 394 */
  {118, "D2d^8 ", "P -4 -2n        ", "P -4 n 2                       ", "P -4 n 2           ", "P-4n2     ", "     ", SpaceGroups::TETRA }, /* 395 */
  {119, "D2d^9 ", "I -4 -2         ", "I -4 m 2                       ", "I -4 m 2           ", "I-4m2     ", "     ", SpaceGroups::TETRA }, /* 396 */
  {120, "D2d^10", "I -4 -2c        ", "I -4 c 2                       ", "I -4 c 2           ", "I-4c2     ", "     ", SpaceGroups::TETRA }, /* 397 */
  {121, "D2d^11", "I -4 2          ", "I -4 2 m                       ", "I -4 2 m           ", "I-42m     ", "     ", SpaceGroups::TETRA }, /* 398 */
  {122, "D2d^12", "I -4 2bw        ", "I -4 2 d                       ", "I -4 2 d           ", "I-42d     ", "     ", SpaceGroups::TETRA }, /* 399 */
  {123, "D4h^1 ", "-P 4 2          ", "P 4/m m m                      ", "P 4/m 2/m 2/m      ", "P4/mmm    ", "     ", SpaceGroups::TETRA }, /* 400 */
  {124, "D4h^2 ", "-P 4 2c         ", "P 4/m c c                      ", "P 4/m 2/c 2/c      ", "P4/mcc    ", "     ", SpaceGroups::TETRA }, /* 401 */
  {125, "D4h^3 ", "P 4 2 -1ab      ", "P 4/n b m                      ", "P 4/n 2/b 2/m      ", "P4/nbm    ", "1    ", SpaceGroups::TETRA }, /* 402 */
  {125, "D4h^3 ", "-P 4a 2b        ", "P 4/n b m                      ", "P 4/n 2/b 2/m      ", "P4/nbm    ", "2    ", SpaceGroups::TETRA }, /* 403 */
  {126, "D4h^4 ", "P 4 2 -1n       ", "P 4/n n c                      ", "P 4/n 2/n 2/c      ", "P4/nnc    ", "1    ", SpaceGroups::TETRA }, /* 404 */
  {126, "D4h^4 ", "-P 4a 2bc       ", "P 4/n n c                      ", "P 4/n 2/n 2/c      ", "P4/nnc    ", "2    ", SpaceGroups::TETRA }, /* 405 */
  {127, "D4h^5 ", "-P 4 2ab        ", "P 4/m b m                      ", "P 4/m 2_1/b m      ", "P4/mbm    ", "     ", SpaceGroups::TETRA }, /* 406 */
  {128, "D4h^6 ", "-P 4 2n         ", "P 4/m n c                      ", "P 4/m 2_1/n c      ", "P4/mnc    ", "     ", SpaceGroups::TETRA }, /* 407 */
  {129, "D4h^7 ", "P 4ab 2ab -1ab  ", "P 4/n m m                      ", "P 4/n 2_1/m m      ", "P4/nmm    ", "1    ", SpaceGroups::TETRA }, /* 408 */
  {129, "D4h^7 ", "-P 4a 2a        ", "P 4/n m m                      ", "P 4/n 2_1/m m      ", "P4/nmm    ", "2    ", SpaceGroups::TETRA }, /* 409 */
  {130, "D4h^8 ", "P 4ab 2n -1ab   ", "P 4/n c c                      ", "P 4/n 2_1/c c      ", "P4/ncc    ", "1    ", SpaceGroups::TETRA }, /* 410 */
  {130, "D4h^8 ", "-P 4a 2ac       ", "P 4/n c c                      ", "P 4/n 2_1/c c      ", "P4/ncc    ", "2    ", SpaceGroups::TETRA }, /* 411 */
  {131, "D4h^9 ", "-P 4c 2         ", "P 4_2/m m c                    ", "P 4_2/m 2/m 2/c    ", "P4_2/mmc  ", "     ", SpaceGroups::TETRA }, /* 412 */
  {132, "D4h^10", "-P 4c 2c        ", "P 4_2/m c m                    ", "P 4_2/m 2/c 2/m    ", "P4_2/mcm  ", "     ", SpaceGroups::TETRA }, /* 413 */
  {133, "D4h^11", "P 4n 2c -1n     ", "P 4_2/n b c                    ", "P 4_2/n 2/b 2/c    ", "P4_2/nbc  ", "1    ", SpaceGroups::TETRA }, /* 414 */
  {133, "D4h^11", "-P 4ac 2b       ", "P 4_2/n b c                    ", "P 4_2/n 2/b 2/c    ", "P4_2/nbc  ", "2    ", SpaceGroups::TETRA }, /* 415 */
  {134, "D4h^12", "P 4n 2 -1n      ", "P 4_2/n n m                    ", "P 4_2/n 2/n 2/m    ", "P4_2/nnm  ", "1    ", SpaceGroups::TETRA }, /* 416 */
  {134, "D4h^12", "-P 4ac 2bc      ", "P 4_2/n n m                    ", "P 4_2/n 2/n 2/m    ", "P4_2/nnm  ", "2    ", SpaceGroups::TETRA }, /* 417 */
  {135, "D4h^13", "-P 4c 2ab       ", "P 4_2/m b c                    ", "P 4_2/m 2_1/b 2/c  ", "P4_2/mbc  ", "     ", SpaceGroups::TETRA }, /* 418 */
  {136, "D4h^14", "-P 4n 2n        ", "P 4_2/m n m                    ", "P 4_2/m 2_1/n 2/m  ", "P4_2/mnm  ", "     ", SpaceGroups::TETRA }, /* 419 */
  {137, "D4h^15", "P 4n 2n -1n     ", "P 4_2/n m c                    ", "P 4_2/n 2_1/m 2/c  ", "P4_2/nmc  ", "1    ", SpaceGroups::TETRA }, /* 420 */
  {137, "D4h^15", "-P 4ac 2a       ", "P 4_2/n m c                    ", "P 4_2/n 2_1/m 2/c  ", "P4_2/nmc  ", "2    ", SpaceGroups::TETRA }, /* 421 */
  {138, "D4h^16", "P 4n 2ab -1n    ", "P 4_2/n c m                    ", "P 4_2/n 2_1/c 2/m  ", "P4_2/ncm  ", "1    ", SpaceGroups::TETRA }, /* 422 */
  {138, "D4h^16", "-P 4ac 2ac      ", "P 4_2/n c m                    ", "P 4_2/n 2_1/c 2/m  ", "P4_2/ncm  ", "2    ", SpaceGroups::TETRA }, /* 423 */
  {139, "D4h^17", "-I 4 2          ", "I 4/m m m                      ", "I 4/m 2/m 2/m      ", "I4/mmm    ", "     ", SpaceGroups::TETRA }, /* 424 */
  {140, "D4h^18", "-I 4 2c         ", "I 4/m c m                      ", "I 4/m 2/c 2/m      ", "I4/mcm    ", "     ", SpaceGroups::TETRA }, /* 425 */
  {141, "D4h^19", "I 4bw 2bw -1bw  ", "I 4_1/a m d                    ", "I 4_1/a 2/m 2/d    ", "I4_1/amd  ", "1    ", SpaceGroups::TETRA }, /* 426 */
  {141, "D4h^19", "-I 4bd 2        ", "I 4_1/a m d                    ", "I 4_1/a 2/m 2/d    ", "I4_1/amd  ", "2    ", SpaceGroups::TETRA }, /* 427 */
  {142, "D4h^20", "I 4bw 2aw -1bw  ", "I 4_1/a c d                    ", "I 4_1/a 2/c 2/d    ", "I4_1/acd  ", "1    ", SpaceGroups::TETRA }, /* 428 */
  {142, "D4h^20", "-I 4bd 2c       ", "I 4_1/a c d                    ", "I 4_1/a 2/c 2/d    ", "I4_1/acd  ", "2    ", SpaceGroups::TETRA }, /* 429 */
  {143, "C3^1  ", "P 3             ", "P 3                            ", "P 3                ", "P3        ", "     ", SpaceGroups::TRIGO }, /* 430 */
  {144, "C3^2  ", "P 31            ", "P 3_1                          ", "P 3_1              ", "P3_1      ", "     ", SpaceGroups::TRIGO }, /* 431 */
  {145, "C3^3  ", "P 32            ", "P 3_2                          ", "P 3_2              ", "P3_2      ", "     ", SpaceGroups::TRIGO }, /* 432 */
  {146, "C3^4  ", "R 3             ", "R 3                            ", "R 3                ", "R3        ", "H    ", SpaceGroups::RHOMB }, /* 433 */
  {146, "C3^4  ", "P 3*            ", "R 3                            ", "R 3                ", "R3        ", "R    ", SpaceGroups::RHOMB }, /* 434 */
  {147, "C3i^1 ", "-P 3            ", "P -3                           ", "P -3               ", "P-3       ", "     ", SpaceGroups::TRIGO }, /* 435 */
  {148, "C3i^2 ", "-R 3            ", "R -3                           ", "R -3               ", "R-3       ", "H    ", SpaceGroups::RHOMB }, /* 436 */
  {148, "C3i^2 ", "-P 3*           ", "R -3                           ", "R -3               ", "R-3       ", "R    ", SpaceGroups::RHOMB }, /* 437 */
  {149, "D3^1  ", "P 3 2           ", "P 3 1 2                        ", "P 3 1 2            ", "P312      ", "     ", SpaceGroups::TRIGO }, /* 438 */
  {150, "D3^2  ", "P 3 2=          ", "P 3 2 1                        ", "P 3 2 1            ", "P321      ", "     ", SpaceGroups::TRIGO }, /* 439 */
  {151, "D3^3  ", "P 31 2c (0 0 1) ", "P 3_1 1 2                      ", "P 3_1 1 2          ", "P3_112    ", "     ", SpaceGroups::TRIGO }, /* 440 */
  {152, "D3^4  ", "P 31 2=         ", "P 3_1 2 1                      ", "P 3_1 2 1          ", "P3_121    ", "     ", SpaceGroups::TRIGO }, /* 441 */
  {153, "D3^5  ", "P 32 2c (0 0 -1)", "P 3_2 1 2                      ", "P 3_2 1 2          ", "P3_212    ", "     ", SpaceGroups::TRIGO }, /* 442 */
  {154, "D3^6  ", "P 32 2=         ", "P 3_2 2 1                      ", "P 3_2 2 1          ", "P3_221    ", "     ", SpaceGroups::TRIGO }, /* 443 */
  {155, "D3^7  ", "R 3 2=          ", "R 3 2                          ", "R 3 2              ", "R32       ", "H    ", SpaceGroups::RHOMB }, /* 444 */
  {155, "D3^7  ", "P 3* 2          ", "R 3 2                          ", "R 3 2              ", "R32       ", "R    ", SpaceGroups::RHOMB }, /* 445 */
  {156, "C3v^1 ", "P 3 -2=         ", "P 3 m 1                        ", "P 3 m 1            ", "P3m1      ", "     ", SpaceGroups::TRIGO }, /* 446 */
  {157, "C3v^2 ", "P 3 -2          ", "P 3 1 m                        ", "P 3 1 m            ", "P31m      ", "     ", SpaceGroups::TRIGO }, /* 447 */
  {158, "C3v^3 ", "P 3 -2=c        ", "P 3 c 1                        ", "P 3 c 1            ", "P3c1      ", "     ", SpaceGroups::TRIGO }, /* 448 */
  {159, "C3v^4 ", "P 3 -2c         ", "P 3 1 c                        ", "P 3 1 c            ", "P31c      ", "     ", SpaceGroups::TRIGO }, /* 449 */
  {160, "C3v^5 ", "R 3 -2=         ", "R 3 m                          ", "R 3 m              ", "R3m       ", "H    ", SpaceGroups::RHOMB }, /* 450 */
  {160, "C3v^5 ", "P 3* -2         ", "R 3 m                          ", "R 3 m              ", "R3m       ", "R    ", SpaceGroups::RHOMB }, /* 451 */
  {161, "C3v^6 ", "R 3 -2=c        ", "R 3 c                          ", "R 3 c              ", "R3c       ", "H    ", SpaceGroups::RHOMB }, /* 452 */
  {161, "C3v^6 ", "P 3* -2n        ", "R 3 c                          ", "R 3 c              ", "R3c       ", "R    ", SpaceGroups::RHOMB }, /* 453 */
  {162, "D3d^1 ", "-P 3 2          ", "P -3 1 m                       ", "P -3 1 2/m         ", "P-31m     ", "     ", SpaceGroups::TRIGO }, /* 454 */
  {163, "D3d^2 ", "-P 3 2c         ", "P -3 1 c                       ", "P -3 1 2/c         ", "P-31c     ", "     ", SpaceGroups::TRIGO }, /* 455 */
  {164, "D3d^3 ", "-P 3 2=         ", "P -3 m 1                       ", "P -3 2/m 1         ", "P-3m1     ", "     ", SpaceGroups::TRIGO }, /* 456 */
  {165, "D3d^4 ", "-P 3 2=c        ", "P -3 c 1                       ", "P -3 2/c 1         ", "P-3c1     ", "     ", SpaceGroups::TRIGO }, /* 457 */
  {166, "D3d^5 ", "-R 3 2=         ", "R -3 m                         ", "R -3 2/m           ", "R-3m      ", "H    ", SpaceGroups::RHOMB }, /* 458 */
  {166, "D3d^5 ", "-P 3* 2         ", "R -3 m                         ", "R -3 2/m           ", "R-3m      ", "R    ", SpaceGroups::RHOMB }, /* 459 */
  {167, "D3d^6 ", "-R 3 2=c        ", "R -3 c                         ", "R -3 2/c           ", "R-3c      ", "H    ", SpaceGroups::RHOMB }, /* 460 */
  {167, "D3d^6 ", "-P 3* 2n        ", "R -3 c                         ", "R -3 2/c           ", "R-3c      ", "R    ", SpaceGroups::RHOMB }, /* 461 */
  {168, "C6^1  ", "P 6             ", "P 6                            ", "P 6                ", "P6        ", "     ", SpaceGroups::HEXA }, /* 462 */
  {169, "C6^2  ", "P 61            ", "P 6_1                          ", "P 6_1              ", "P6_1      ", "     ", SpaceGroups::HEXA }, /* 463 */
  {170, "C6^3  ", "P 65            ", "P 6_5                          ", "P 6_5              ", "P6_5      ", "     ", SpaceGroups::HEXA }, /* 464 */
  {171, "C6^4  ", "P 62            ", "P 6_2                          ", "P 6_2              ", "P6_2      ", "     ", SpaceGroups::HEXA }, /* 465 */
  {172, "C6^5  ", "P 64            ", "P 6_4                          ", "P 6_4              ", "P6_4      ", "     ", SpaceGroups::HEXA }, /* 466 */
  {173, "C6^6  ", "P 6c            ", "P 6_3                          ", "P 6_3              ", "P6_3      ", "     ", SpaceGroups::HEXA }, /* 467 */
  {174, "C3h^1 ", "P -6            ", "P -6                           ", "P -6               ", "P-6       ", "     ", SpaceGroups::HEXA }, /* 468 */
  {175, "C6h^1 ", "-P 6            ", "P 6/m                          ", "P 6/m              ", "P6/m      ", "     ", SpaceGroups::HEXA }, /* 469 */
  {176, "C6h^2 ", "-P 6c           ", "P 6_3/m                        ", "P 6_3/m            ", "P6_3/m    ", "     ", SpaceGroups::HEXA }, /* 470 */
  {177, "D6^1  ", "P 6 2           ", "P 6 2 2                        ", "P 6 2 2            ", "P622      ", "     ", SpaceGroups::HEXA }, /* 471 */
  {178, "D6^2  ", "P 61 2 (0 0 -1) ", "P 6_1 2 2                      ", "P 6_1 2 2          ", "P6_122    ", "     ", SpaceGroups::HEXA }, /* 472 */
  {179, "D6^3  ", "P 65 2 (0 0 1)  ", "P 6_5 2 2                      ", "P 6_5 2 2          ", "P6_522    ", "     ", SpaceGroups::HEXA }, /* 473 */
  {180, "D6^4  ", "P 62 2c (0 0 1) ", "P 6_2 2 2                      ", "P 6_2 2 2          ", "P6_222    ", "     ", SpaceGroups::HEXA }, /* 474 */
  {181, "D6^5  ", "P 64 2c (0 0 -1)", "P 6_4 2 2                      ", "P 6_4 2 2          ", "P6_422    ", "     ", SpaceGroups::HEXA }, /* 475 */
  {182, "D6^6  ", "P 6c 2c         ", "P 6_3 2 2                      ", "P 6_3 2 2          ", "P6_322    ", "     ", SpaceGroups::HEXA }, /* 476 */
  {183, "C6v^1 ", "P 6 -2          ", "P 6 m m                        ", "P 6 m m            ", "P6mm      ", "     ", SpaceGroups::HEXA }, /* 477 */
  {184, "C6v^2 ", "P 6 -2c         ", "P 6 c c                        ", "P 6 c c            ", "P6cc      ", "     ", SpaceGroups::HEXA }, /* 478 */
  {185, "C6v^3 ", "P 6c -2         ", "P 6_3 c m                      ", "P 6_3 c m          ", "P6_3cm    ", "     ", SpaceGroups::HEXA }, /* 479 */
  {186, "C6v^4 ", "P 6c -2c        ", "P 6_3 m c                      ", "P 6_3 m c          ", "P6_3mc    ", "     ", SpaceGroups::HEXA }, /* 480 */
  {187, "D3h^1 ", "P -6 2          ", "P -6 m 2                       ", "P -6 m 2           ", "P-6m2     ", "     ", SpaceGroups::HEXA }, /* 481 */
  {188, "D3h^2 ", "P -6c 2         ", "P -6 c 2                       ", "P -6 c 2           ", "P-6c2     ", "     ", SpaceGroups::HEXA }, /* 482 */
  {189, "D3h^3 ", "P -6 -2         ", "P -6 2 m                       ", "P -6 2 m           ", "P-62m     ", "     ", SpaceGroups::HEXA }, /* 483 */
  {190, "D3h^4 ", "P -6c -2c       ", "P -6 2 c                       ", "P -6 2 c           ", "P-62c     ", "     ", SpaceGroups::HEXA }, /* 484 */
  {191, "D6h^1 ", "-P 6 2          ", "P 6/m m m                      ", "P 6/m 2/m 2/m      ", "P6/mmm    ", "     ", SpaceGroups::HEXA }, /* 485 */
  {192, "D6h^2 ", "-P 6 2c         ", "P 6/m c c                      ", "P 6/m 2/c 2/c      ", "P6/mcc    ", "     ", SpaceGroups::HEXA }, /* 486 */
  {193, "D6h^3 ", "-P 6c 2         ", "P 6_3/m c m                    ", "P 6_3/m 2/c 2/m    ", "P6_3/mcm  ", "     ", SpaceGroups::HEXA }, /* 487 */
  {194, "D6h^4 ", "-P 6c 2c        ", "P 6_3/m m c                    ", "P 6_3/m 2/m 2/c    ", "P6_3/mmc  ", "     ", SpaceGroups::HEXA }, /* 488 */
  {195, "T^1   ", "P 2 2 3         ", "P 2 3                          ", "P 2 3              ", "P23       ", "     ", SpaceGroups::CUBIC }, /* 489 */
  {196, "T^2   ", "F 2 2 3         ", "F 2 3                          ", "F 2 3              ", "F23       ", "     ", SpaceGroups::CUBIC }, /* 490 */
  {197, "T^3   ", "I 2 2 3         ", "I 2 3                          ", "I 2 3              ", "I23       ", "     ", SpaceGroups::CUBIC }, /* 491 */
  {198, "T^4   ", "P 2ac 2ab 3     ", "P 2_1 3                        ", "P 2_1 3            ", "P2_13     ", "     ", SpaceGroups::CUBIC }, /* 492 */
  {199, "T^5   ", "I 2b 2c 3       ", "I 2_1 3                        ", "I 2_1 3            ", "I2_13     ", "     ", SpaceGroups::CUBIC }, /* 493 */
  {200, "Th^1  ", "-P 2 2 3        ", "P m 3                          ", "P 2/m -3           ", "Pm3       ", "     ", SpaceGroups::CUBIC }, /* 494 */
  {201, "Th^2  ", "P 2 2 3 -1n     ", "P n 3                          ", "P 2/n -3           ", "Pn3       ", "1    ", SpaceGroups::CUBIC }, /* 495 */
  {201, "Th^2  ", "-P 2ab 2bc 3    ", "P n 3                          ", "P 2/n -3           ", "Pn3       ", "2    ", SpaceGroups::CUBIC }, /* 496 */
  {202, "Th^3  ", "-F 2 2 3        ", "F m 3                          ", "F 2/m -3           ", "Fm3       ", "     ", SpaceGroups::CUBIC }, /* 497 */
  {203, "Th^4  ", "F 2 2 3 -1d     ", "F d 3                          ", "F 2/d -3           ", "Fd3       ", "1    ", SpaceGroups::CUBIC }, /* 498 */
  {203, "Th^4  ", "-F 2uv 2vw 3    ", "F d 3                          ", "F 2/d -3           ", "Fd3       ", "2    ", SpaceGroups::CUBIC }, /* 499 */
  {204, "Th^5  ", "-I 2 2 3        ", "I m 3                          ", "I 2/m -3           ", "Im3       ", "     ", SpaceGroups::CUBIC }, /* 500 */
  {205, "Th^6  ", "-P 2ac 2ab 3    ", "P a 3                          ", "P 2_1/a -3         ", "Pa3       ", "     ", SpaceGroups::CUBIC }, /* 501 */
  {206, "Th^7  ", "-I 2b 2c 3      ", "I a 3                          ", "I 2_1/a -3         ", "Ia3       ", "     ", SpaceGroups::CUBIC }, /* 502 */
  {207, "O^1   ", "P 4 2 3         ", "P 4 3 2                        ", "P 4 3 2            ", "P432      ", "     ", SpaceGroups::CUBIC }, /* 503 */
  {208, "O^2   ", "P 4n 2 3        ", "P 4_2 3 2                      ", "P 4_2 3 2          ", "P4_232    ", "     ", SpaceGroups::CUBIC }, /* 504 */
  {209, "O^3   ", "F 4 2 3         ", "F 4 3 2                        ", "F 4 3 2            ", "F432      ", "     ", SpaceGroups::CUBIC }, /* 505 */
  {210, "O^4   ", "F 4d 2 3        ", "F 4_1 3 2                      ", "F 4_1 3 2          ", "F4_132    ", "     ", SpaceGroups::CUBIC }, /* 506 */
  {211, "O^5   ", "I 4 2 3         ", "I 4 3 2                        ", "I 4 3 2            ", "I432      ", "     ", SpaceGroups::CUBIC }, /* 507 */
  {212, "O^6   ", "P 4acd 2ab 3    ", "P 4_3 3 2                      ", "P 4_3 3 2          ", "P4_332    ", "     ", SpaceGroups::CUBIC }, /* 508 */
  {213, "O^7   ", "P 4bd 2ab 3     ", "P 4_1 3 2                      ", "P 4_1 3 2          ", "P4_132    ", "     ", SpaceGroups::CUBIC }, /* 509 */
  {214, "O^8   ", "I 4bd 2c 3      ", "I 4_1 3 2                      ", "I 4_1 3 2          ", "I4_132    ", "     ", SpaceGroups::CUBIC }, /* 510 */
  {215, "Td^1  ", "P -4 2 3        ", "P -4 3 m                       ", "P -4 3 m           ", "P-43m     ", "     ", SpaceGroups::CUBIC }, /* 511 */
  {216, "Td^2  ", "F -4 2 3        ", "F -4 3 m                       ", "F -4 3 m           ", "F-43m     ", "     ", SpaceGroups::CUBIC }, /* 512 */
  {217, "Td^3  ", "I -4 2 3        ", "I -4 3 m                       ", "I -4 3 m           ", "I-43m     ", "     ", SpaceGroups::CUBIC }, /* 513 */
  {218, "Td^4  ", "P -4n 2 3       ", "P -4 3 n                       ", "P -4 3 n           ", "P-43n     ", "     ", SpaceGroups::CUBIC }, /* 514 */
  {219, "Td^5  ", "F -4c 2 3       ", "F -4 3 c                       ", "F -4 3 c           ", "F-43c     ", "     ", SpaceGroups::CUBIC }, /* 515 */
  {220, "Td^6  ", "I -4bd 2c 3     ", "I -4 3 d                       ", "I -4 3 d           ", "I-43d     ", "     ", SpaceGroups::CUBIC }, /* 516 */
  {221, "Oh^1  ", "-P 4 2 3        ", "P m -3 m                       ", "P 4/m -3 2/m       ", "Pm-3m     ", "     ", SpaceGroups::CUBIC }, /* 517 */
  {222, "Oh^2  ", "P 4 2 3 -1n     ", "P n -3 n                       ", "P 4/n -3 2/n       ", "Pn-3n     ", "1    ", SpaceGroups::CUBIC }, /* 518 */
  {222, "Oh^2  ", "-P 4a 2bc 3     ", "P n -3 n                       ", "P 4/n -3 2/n       ", "Pn-3n     ", "2    ", SpaceGroups::CUBIC }, /* 519 */
  {223, "Oh^3  ", "-P 4n 2 3       ", "P m -3 n                       ", "P 4_2/m -3 2/n     ", "Pm-3n     ", "     ", SpaceGroups::CUBIC }, /* 520 */
  {224, "Oh^4  ", "P 4n 2 3 -1n    ", "P n -3 m                       ", "P 4_2/n -3 2/m     ", "Pn-3m     ", "1    ", SpaceGroups::CUBIC }, /* 521 */
  {224, "Oh^4  ", "-P 4bc 2bc 3    ", "P n -3 m                       ", "P 4_2/n -3 2/m     ", "Pn-3m     ", "2    ", SpaceGroups::CUBIC }, /* 522 */
  {225, "Oh^5  ", "-F 4 2 3        ", "F m -3 m                       ", "F 4/m -3 2/m       ", "Fm-3m     ", "     ", SpaceGroups::CUBIC }, /* 523 */
  {226, "Oh^6  ", "-F 4c 2 3       ", "F m -3 c                       ", "F 4/m -3 2/c       ", "Fm-3c     ", "     ", SpaceGroups::CUBIC }, /* 524 */
  {227, "Oh^7  ", "F 4d 2 3 -1d    ", "F d -3 m                       ", "F 4_1/d -3 2/m     ", "Fd-3m     ", "1    ", SpaceGroups::CUBIC }, /* 525 */
  {227, "Oh^7  ", "-F 4vw 2vw 3    ", "F d -3 m                       ", "F 4_1/d -3 2/m     ", "Fd-3m     ", "2    ", SpaceGroups::CUBIC }, /* 526 */
  {228, "Oh^8  ", "F 4d 2 3 -1cd   ", "F d -3 c                       ", "F 4_1/d -3 2/c     ", "Fd-3c     ", "1    ", SpaceGroups::CUBIC }, /* 527 */
  {228, "Oh^8  ", "-F 4cvw 2vw 3   ", "F d -3 c                       ", "F 4_1/d -3 2/c     ", "Fd-3c     ", "2    ", SpaceGroups::CUBIC }, /* 528 */
  {229, "Oh^9  ", "-I 4 2 3        ", "I m -3 m                       ", "I 4/m -3 2/m       ", "Im-3m     ", "     ", SpaceGroups::CUBIC }, /* 529 */
  {230, "Oh^10 ", "-I 4bd 2c 3     ", "I a -3 d                       ", "I 4_1/a -3 2/d     ", "Ia-3d     ", "     ", SpaceGroups::CUBIC }, /* 530 */
};

#endif // AVOGADRO_CORE_CRYSTALTOOLS_H
