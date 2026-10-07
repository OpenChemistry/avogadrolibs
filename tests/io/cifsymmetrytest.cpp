/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/io/cifsymmetry.h>

#include <avogadro/core/spacegroups.h>

#include <string>

using Avogadro::Core::SpaceGroups;
using Avogadro::Io::CifSymmetry;
using Avogadro::Io::readCifSymmetry;

namespace {

// The symmetry loop of crystals/zeolites/FAU.cif: space group 227 with origin
// choice 2, which the symbol in the file ('F d 3 m') does not say.
const char* const fauOperations = R"CIF(
'+x,+y,+z'
'+x,1/2+y,1/2+z'
'1/2+x,1/2+y,+z'
'1/2+x,+y,1/2+z'
'+z,+x,+y'
'+z,1/2+x,1/2+y'
'1/2+z,1/2+x,+y'
'1/2+z,+x,1/2+y'
'+y,+z,+x'
'+y,1/2+z,1/2+x'
'1/2+y,1/2+z,+x'
'1/2+y,+z,1/2+x'
'-x,1/4+y,1/4+z'
'-x,3/4+y,3/4+z'
'1/2-x,3/4+y,1/4+z'
'1/2-x,1/4+y,3/4+z'
'-z,1/4+x,1/4+y'
'-z,3/4+x,3/4+y'
'1/2-z,3/4+x,1/4+y'
'1/2-z,1/4+x,3/4+y'
'-y,1/4+z,1/4+x'
'-y,3/4+z,3/4+x'
'1/2-y,3/4+z,1/4+x'
'1/2-y,1/4+z,3/4+x'
'1/4+x,-y,1/4+z'
'1/4+x,1/2-y,3/4+z'
'3/4+x,1/2-y,1/4+z'
'3/4+x,-y,3/4+z'
'1/4+z,-x,1/4+y'
'1/4+z,1/2-x,3/4+y'
'3/4+z,1/2-x,1/4+y'
'3/4+z,-x,3/4+y'
'1/4+y,-z,1/4+x'
'1/4+y,1/2-z,3/4+x'
'3/4+y,1/2-z,1/4+x'
'3/4+y,-z,3/4+x'
'1/4-x,3/4-y,1/2+z'
'1/4-x,1/4-y,+z'
'3/4-x,1/4-y,1/2+z'
'3/4-x,3/4-y,+z'
'1/4-z,3/4-x,1/2+y'
'1/4-z,1/4-x,+y'
'3/4-z,1/4-x,1/2+y'
'3/4-z,3/4-x,+y'
'1/4-y,3/4-z,1/2+x'
'1/4-y,1/4-z,+x'
'3/4-y,1/4-z,1/2+x'
'3/4-y,3/4-z,+x'
'+y,+x,+z'
'+y,1/2+x,1/2+z'
'1/2+y,1/2+x,+z'
'1/2+y,+x,1/2+z'
'+x,+z,+y'
'+x,1/2+z,1/2+y'
'1/2+x,1/2+z,+y'
'1/2+x,+z,1/2+y'
'+z,+y,+x'
'+z,1/2+y,1/2+x'
'1/2+z,1/2+y,+x'
'1/2+z,+y,1/2+x'
'1/4+y,-x,1/4+z'
'1/4+y,1/2-x,3/4+z'
'3/4+y,1/2-x,1/4+z'
'3/4+y,-x,3/4+z'
'1/4+x,-z,1/4+y'
'1/4+x,1/2-z,3/4+y'
'3/4+x,1/2-z,1/4+y'
'3/4+x,-z,3/4+y'
'1/4+z,-y,1/4+x'
'1/4+z,1/2-y,3/4+x'
'3/4+z,1/2-y,1/4+x'
'3/4+z,-y,3/4+x'
'-y,1/4+x,1/4+z'
'-y,3/4+x,3/4+z'
'1/2-y,3/4+x,1/4+z'
'1/2-y,1/4+x,3/4+z'
'-x,1/4+z,1/4+y'
'-x,3/4+z,3/4+y'
'1/2-x,3/4+z,1/4+y'
'1/2-x,1/4+z,3/4+y'
'-z,1/4+y,1/4+x'
'-z,3/4+y,3/4+x'
'1/2-z,3/4+y,1/4+x'
'1/2-z,1/4+y,3/4+x'
'3/4-y,1/4-x,1/2+z'
'3/4-y,3/4-x,+z'
'1/4-y,3/4-x,1/2+z'
'1/4-y,1/4-x,+z'
'3/4-x,1/4-z,1/2+y'
'3/4-x,3/4-z,+y'
'1/4-x,3/4-z,1/2+y'
'1/4-x,1/4-z,+y'
'3/4-z,1/4-y,1/2+x'
'3/4-z,3/4-y,+x'
'1/4-z,3/4-y,1/2+x'
'1/4-z,1/4-y,+x'
'-x,-y,-z'
'-x,1/2-y,1/2-z'
'1/2-x,1/2-y,-z'
'1/2-x,-y,1/2-z'
'-z,-x,-y'
'-z,1/2-x,1/2-y'
'1/2-z,1/2-x,-y'
'1/2-z,-x,1/2-y'
'-y,-z,-x'
'-y,1/2-z,1/2-x'
'1/2-y,1/2-z,-x'
'1/2-y,-z,1/2-x'
'+x,3/4-y,3/4-z'
'+x,1/4-y,1/4-z'
'1/2+x,1/4-y,3/4-z'
'1/2+x,3/4-y,1/4-z'
'+z,3/4-x,3/4-y'
'+z,1/4-x,1/4-y'
'1/2+z,1/4-x,3/4-y'
'1/2+z,3/4-x,1/4-y'
'+y,3/4-z,3/4-x'
'+y,1/4-z,1/4-x'
'1/2+y,1/4-z,3/4-x'
'1/2+y,3/4-z,1/4-x'
'3/4-x,+y,3/4-z'
'3/4-x,1/2+y,1/4-z'
'1/4-x,1/2+y,3/4-z'
'1/4-x,+y,1/4-z'
'3/4-z,+x,3/4-y'
'3/4-z,1/2+x,1/4-y'
'1/4-z,1/2+x,3/4-y'
'1/4-z,+x,1/4-y'
'3/4-y,+z,3/4-x'
'3/4-y,1/2+z,1/4-x'
'1/4-y,1/2+z,3/4-x'
'1/4-y,+z,1/4-x'
'3/4+x,1/4+y,1/2-z'
'3/4+x,3/4+y,-z'
'1/4+x,3/4+y,1/2-z'
'1/4+x,1/4+y,-z'
'3/4+z,1/4+x,1/2-y'
'3/4+z,3/4+x,-y'
'1/4+z,3/4+x,1/2-y'
'1/4+z,1/4+x,-y'
'3/4+y,1/4+z,1/2-x'
'3/4+y,3/4+z,-x'
'1/4+y,3/4+z,1/2-x'
'1/4+y,1/4+z,-x'
'-y,-x,-z'
'-y,1/2-x,1/2-z'
'1/2-y,1/2-x,-z'
'1/2-y,-x,1/2-z'
'-x,-z,-y'
'-x,1/2-z,1/2-y'
'1/2-x,1/2-z,-y'
'1/2-x,-z,1/2-y'
'-z,-y,-x'
'-z,1/2-y,1/2-x'
'1/2-z,1/2-y,-x'
'1/2-z,-y,1/2-x'
'3/4-y,+x,3/4-z'
'3/4-y,1/2+x,1/4-z'
'1/4-y,1/2+x,3/4-z'
'1/4-y,+x,1/4-z'
'3/4-x,+z,3/4-y'
'3/4-x,1/2+z,1/4-y'
'1/4-x,1/2+z,3/4-y'
'1/4-x,+z,1/4-y'
'3/4-z,+y,3/4-x'
'3/4-z,1/2+y,1/4-x'
'1/4-z,1/2+y,3/4-x'
'1/4-z,+y,1/4-x'
'+y,3/4-x,3/4-z'
'+y,1/4-x,1/4-z'
'1/2+y,1/4-x,3/4-z'
'1/2+y,3/4-x,1/4-z'
'+x,3/4-z,3/4-y'
'+x,1/4-z,1/4-y'
'1/2+x,1/4-z,3/4-y'
'1/2+x,3/4-z,1/4-y'
'+z,3/4-y,3/4-x'
'+z,1/4-y,1/4-x'
'1/2+z,1/4-y,3/4-x'
'1/2+z,3/4-y,1/4-x'
'1/4+y,3/4+x,1/2-z'
'1/4+y,1/4+x,-z'
'3/4+y,1/4+x,1/2-z'
'3/4+y,3/4+x,-z'
'1/4+x,3/4+z,1/2-y'
'1/4+x,1/4+z,-y'
'3/4+x,1/4+z,1/2-y'
'3/4+x,3/4+z,-y'
'1/4+z,3/4+y,1/2-x'
'1/4+z,1/4+y,-x'
'3/4+z,1/4+y,1/2-x'
'3/4+z,3/4+y,-x'

)CIF";

// crystals/ice/H2O-Ice-IV.cif: 'R -3 c' is the rhombohedral setting here.
const char* const iceIvOperations = R"CIF(
  'x,y,z'
  '1/2-x,1/2-z,1/2-y'
  '-z,-x,-y'
  '1/2+y,1/2+x,1/2+z'
  'y,z,x'
  '1/2-z,1/2-y,1/2-x'
  '-x,-y,-z'
  '1/2+x,1/2+z,1/2+y'
  'z,x,y'
  '1/2-y,1/2-x,1/2-z'
  '-y,-z,-x'
  '1/2+z,1/2+y,1/2+x'
)CIF";

} // namespace

TEST(CifSymmetryTest, izaZeoliteOriginChoice2)
{
  std::string cif = R"CIF(data_FAU
#**************************************************************************
# CIF taken from the IZA-SC Database of Zeolite Structures
#**************************************************************************

_cell_length_a                  24.3450(0)
_symmetry_space_group_name_H-M     'F d 3 m'
_symmetry_Int_Tables_number         227
_space_group.IT_coordinate_system_code  '2'
_symmetry_cell_setting             cubic

loop_
_symmetry_equiv_pos_as_xyz
)CIF";
  cif += fauOperations;
  cif += R"CIF(
loop_
_atom_site_label
_atom_site_fract_x
_atom_site_fract_y
_atom_site_fract_z
T1  0.12500  0.12500  0.12500
)CIF";

  CifSymmetry symmetry = readCifSymmetry(cif);
  EXPECT_EQ(symmetry.operations.size(), 192u);
  EXPECT_EQ(symmetry.operations.front(), "+x,+y,+z");
  unsigned short origin2 = SpaceGroups::hallNumber("F d -3 m :2");
  ASSERT_NE(origin2, 0);
  EXPECT_EQ(symmetry.hallFromOperations, origin2);
  EXPECT_EQ(symmetry.hallNumber(), origin2);
  EXPECT_EQ(symmetry.hallFromSymbol, 0);
  EXPECT_TRUE(symmetry.hallSymbol.empty());
}

TEST(CifSymmetryTest, rhombohedralIceIv)
{
  std::string cif = R"CIF(data_global
_chemical_name_mineral 'Ice IV'
loop_
_publ_author_name
'Engelhardt H'
'Kamb B'
_journal_volume 75
_publ_section_title
;
 Structure of ice IV, a metastable high-pressure phase
 loop_
 _symmetry_equiv_pos_as_xyz
 'x,y,z'
;
_cell_length_a 7.60
_symmetry_space_group_name_H-M 'R -3 c'
loop_
_space_group_symop_operation_xyz
)CIF";
  cif += iceIvOperations;
  cif += R"CIF(loop_
_atom_site_label
_atom_site_fract_x
_atom_site_fract_y
_atom_site_fract_z
O1   0.38040  -0.11090  -0.23960
)CIF";

  CifSymmetry symmetry = readCifSymmetry(cif);
  EXPECT_EQ(symmetry.operations.size(), 12u);
  unsigned short rhombohedral = SpaceGroups::hallNumber("R -3 c :R");
  unsigned short hexagonal = SpaceGroups::hallNumber("R -3 c :H");
  ASSERT_NE(rhombohedral, 0);
  ASSERT_NE(hexagonal, 0);
  EXPECT_NE(rhombohedral, hexagonal);
  EXPECT_EQ(symmetry.hallNumber(), rhombohedral);
}

TEST(CifSymmetryTest, columnsWithIdsAndQuotes)
{
  const char* cif = R"CIF(data_test
loop_
_space_group_symop_id
_space_group_symop_operation_xyz
_space_group_symop_note
1 'x, y, z' .
2 "-x, y+1/2, -z+1/2" 'a note with spaces'
3 -x,-y,-z note3
4 'x, -y+1/2, z+1/2' "it's"
)CIF";
  CifSymmetry symmetry = readCifSymmetry(cif);
  ASSERT_EQ(symmetry.operations.size(), 4u);
  EXPECT_EQ(symmetry.operations[0], "x, y, z");
  EXPECT_EQ(symmetry.operations[1], "-x, y+1/2, -z+1/2");
  EXPECT_EQ(symmetry.operations[2], "-x,-y,-z");
  EXPECT_EQ(symmetry.operations[3], "x, -y+1/2, z+1/2");
  EXPECT_EQ(symmetry.hallNumber(), SpaceGroups::hallNumber("P 1 21/c 1"));
}

TEST(CifSymmetryTest, columnOrderCommentsAndBlankLines)
{
  const char* cif = R"CIF(# a comment before the block
data_test # and one after it

loop_
_symmetry_equiv_pos_as_xyz   # trailing comment
_symmetry_equiv_pos_site_id

# between the rows

'x,y,z'        1
'-x,-y,-z'     2   # the inversion

_cell_length_a 5.0
)CIF";
  CifSymmetry symmetry = readCifSymmetry(cif);
  ASSERT_EQ(symmetry.operations.size(), 2u);
  EXPECT_EQ(symmetry.operations[1], "-x,-y,-z");
  EXPECT_EQ(symmetry.hallNumber(), 2);
}

TEST(CifSymmetryTest, unquotedOperationsWithSpaces)
{
  // older files do not quote "x, y, z" in a one column loop
  const char* cif = R"CIF(data_test
loop_
_symmetry_equiv_pos_as_xyz
x, y, z
-x, -y, -z
x,y,z+1/2
-x, -y ,-z+1/2
)CIF";
  CifSymmetry symmetry = readCifSymmetry(cif);
  ASSERT_EQ(symmetry.operations.size(), 4u);
  EXPECT_EQ(symmetry.operations[0], "x,y,z");
  EXPECT_EQ(symmetry.operations[1], "-x,-y,-z");
  EXPECT_EQ(symmetry.operations[3], "-x,-y,-z+1/2");
}

TEST(CifSymmetryTest, dottedCif2Tag)
{
  const char* cif = R"CIF(data_test
_space_group.name_H-M_alt 'P -1'
_space_group.name_Hall '-P 1'
loop_
_space_group_symop.id
_space_group_symop.operation_xyz
1 x,y,z
2 -x,-y,-z
)CIF";
  CifSymmetry symmetry = readCifSymmetry(cif);
  ASSERT_EQ(symmetry.operations.size(), 2u);
  EXPECT_EQ(symmetry.hallSymbol, "-P 1");
  EXPECT_EQ(symmetry.hallFromOperations, 2);
  EXPECT_EQ(symmetry.hallFromSymbol, 2);
}

TEST(CifSymmetryTest, firstBlockWins)
{
  const char* cif = R"CIF(data_first
_symmetry_space_group_name_Hall '-P 2yn'
loop_
_symmetry_equiv_pos_as_xyz
'x,y,z'
'-x,-y,-z'

data_second
_symmetry_space_group_name_Hall 'P 2yb'
loop_
_symmetry_equiv_pos_as_xyz
'x,y,z'
'-x,y+1/2,-z'
)CIF";
  CifSymmetry symmetry = readCifSymmetry(cif);
  EXPECT_EQ(symmetry.operations.size(), 2u);
  EXPECT_EQ(symmetry.hallSymbol, "-P 2yn");
  EXPECT_EQ(symmetry.hallFromOperations, 2);

  // symmetry that is only in a later block is not used
  const char* second = R"CIF(data_first
_cell_length_a 5.0
data_second
loop_
_symmetry_equiv_pos_as_xyz
'x,y,z'
'-x,-y,-z'
)CIF";
  symmetry = readCifSymmetry(second);
  EXPECT_TRUE(symmetry.operations.empty());
  EXPECT_EQ(symmetry.hallNumber(), 0);
}

TEST(CifSymmetryTest, hallSymbolWhenThereAreNoOperations)
{
  const char* cif = R"CIF(data_test
_symmetry_space_group_name_H-M 'P 21/c'
_symmetry_space_group_name_Hall
;
 -P   2ybc
;
)CIF";
  CifSymmetry symmetry = readCifSymmetry(cif);
  EXPECT_TRUE(symmetry.operations.empty());
  EXPECT_EQ(symmetry.hallSymbol, "-P 2ybc");
  EXPECT_EQ(symmetry.hallFromOperations, 0);
  EXPECT_NE(symmetry.hallFromSymbol, 0);
  EXPECT_EQ(symmetry.hallNumber(), SpaceGroups::hallNumber("-P 2ybc"));

  // operations win over a Hall symbol
  cif = R"CIF(data_test
_space_group_name_Hall '-P 2yn'
loop_
_symmetry_equiv_pos_as_xyz
'x,y,z'
'-x,-y,-z'
)CIF";
  symmetry = readCifSymmetry(cif);
  EXPECT_NE(symmetry.hallFromSymbol, 0);
  EXPECT_EQ(symmetry.hallFromOperations, 2);
  EXPECT_EQ(symmetry.hallNumber(), 2);
}

TEST(CifSymmetryTest, hallSymbolMustBeExact)
{
  // an international symbol, a number and a Hall symbol with an origin shift
  // are not Hall symbols from the table
  for (const char* symbol :
       { "P 21/c", "14", "-P 4c 2 (x,y+1/2,z)", "?", "garbage", "P 2yb x" }) {
    std::string cif =
      std::string("data_test\n_space_group_name_Hall '") + symbol + "'\n";
    CifSymmetry symmetry = readCifSymmetry(cif);
    EXPECT_EQ(symmetry.hallFromSymbol, 0) << symbol;
    EXPECT_EQ(symmetry.hallNumber(), 0) << symbol;
  }
}

TEST(CifSymmetryTest, singleTagAndValue)
{
  CifSymmetry symmetry = readCifSymmetry(
    "data_test\n_symmetry_equiv_pos_as_xyz 'x, y, z'\n_cell_length_a 4\n");
  ASSERT_EQ(symmetry.operations.size(), 1u);
  EXPECT_EQ(symmetry.hallNumber(), 1);
}

TEST(CifSymmetryTest, noSymmetryLoop)
{
  const char* cif = R"CIF(data_test
_cell_length_a 5.0
_symmetry_space_group_name_H-M 'P 1'
loop_
_atom_site_label
_atom_site_fract_x
C1 0.1
)CIF";
  CifSymmetry symmetry = readCifSymmetry(cif);
  EXPECT_TRUE(symmetry.operations.empty());
  EXPECT_TRUE(symmetry.hallSymbol.empty());
  EXPECT_EQ(symmetry.hallNumber(), 0);
}

TEST(CifSymmetryTest, operationsThatAreNotInTheTable)
{
  // a group with an origin shift or a different centering than the table
  const char* cif = R"CIF(data_test
loop_
_symmetry_equiv_pos_as_xyz
'x,y,z'
'-x,-y,-z'
'x+1/12,y,z'
'-x+1/12,-y,-z'
)CIF";
  CifSymmetry symmetry = readCifSymmetry(cif);
  EXPECT_EQ(symmetry.operations.size(), 4u);
  EXPECT_EQ(symmetry.hallNumber(), 0);
}

TEST(CifSymmetryTest, malformedInput)
{
  // none of these may crash or claim a space group
  for (const char* cif : {
         "",
         "   \n\n",
         "garbage",
         "data_",
         "loop_",
         "loop_\n_symmetry_equiv_pos_as_xyz",
         "data_a\nloop_\n_symmetry_equiv_pos_as_xyz\n'x,y,z\n",
         "data_a\nloop_\n_symmetry_equiv_pos_as_xyz\n;\nx,y,z\n",
         "data_a\nloop_\n_symmetry_equiv_pos_as_xyz\n_a\n1\n",
         "data_a\nloop_\n_a\n_symmetry_equiv_pos_as_xyz\n1\n2\n3\n",
         "data_a\n_symmetry_equiv_pos_as_xyz\n",
         "data_a\n_space_group_name_Hall\n_cell_length_a 4\n",
         "data_a\n_space_group_name_Hall '",
         "data_a\nloop_\n_symmetry_equiv_pos_as_xyz\n'x,y' 'a,b,c' '1,2,3'\n",
         "\"\"\"\"\n''''\n;;;;\n#\n",
       }) {
    CifSymmetry symmetry = readCifSymmetry(cif);
    EXPECT_EQ(symmetry.hallNumber(), 0) << cif;
  }
  // a text field that is never closed, and binary junk
  EXPECT_EQ(readCifSymmetry(std::string("data_a\n;\n") + std::string(1000, 'x'))
              .hallNumber(),
            0);
  std::string junk;
  for (int i = 0; i < 5000; ++i)
    junk.push_back(static_cast<char>((i * 7919) % 256));
  EXPECT_EQ(readCifSymmetry(junk).hallNumber(), 0);
}
