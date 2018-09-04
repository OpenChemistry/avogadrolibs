
#ifndef AVOGADRO_CORE_RESIDUE_DATA
#define AVOGADRO_CORE_RESIDUE_DATA

#include <map>
#include <string>
#include <vector>
namespace Avogadro {
namespace Core {

class ResidueData
{
private:
  std::string m_residueName;
  std::vector<std::string> m_residueAtomNames;
  std::vector<std::pair<std::string, std::string>> m_residueSingleBonds;
  std::vector<std::pair<std::string, std::string>> m_residueDoubleBonds;

public:
  ResidueData() {}
  ResidueData(std::string name, std::vector<std::string> atomNames,
              std::vector<std::pair<std::string, std::string>> singleBonds,
              std::vector<std::pair<std::string, std::string>> doubleBonds)
  {
    m_residueName = name;
    m_residueAtomNames = atomNames;
    m_residueSingleBonds = singleBonds;
    m_residueDoubleBonds = doubleBonds;
  }

  ResidueData(const ResidueData& other)
  {
    m_residueName = other.m_residueName;
    m_residueAtomNames = other.m_residueAtomNames;
    m_residueSingleBonds = other.m_residueSingleBonds;
    m_residueDoubleBonds = other.m_residueDoubleBonds;
  }

  ResidueData& operator=(ResidueData other)
  {
    using std::swap;
    swap(*this, other);
    return *this;
  }

  std::vector<std::pair<std::string, std::string>> residueSingleBonds()
  {
    return m_residueSingleBonds;
  }

  std::vector<std::pair<std::string, std::string>> residueDoubleBonds()
  {
    return m_residueDoubleBonds;
  }
};

ResidueData ALAData("ALA",
                    // Atoms
                    { "N", "CA", "C", "O", "CB", "OXT", "H", "H2", "HA", "HB1",
                      "HB2", "HB3", "HXT" },
                    // Single Bonds
                    { { "N", "CA" },
                      { "N", "H" },
                      { "N", "H2" },
                      { "CA", "C" },
                      { "CA", "CB" },
                      { "CA", "HA" },
                      { "C", "OXT" },
                      { "CB", "HB1" },
                      { "CB", "HB2" },
                      { "CB", "HB3" },
                      { "OXT", "HXT" } },
                    // Double Bonds
                    { { "C", "O" } });
ResidueData CYSData("CYS",
                    // Atoms
                    { "N", "CA", "C", "O", "CB", "SG", "OXT", "H", "H2", "HA",
                      "HB2", "HB3", "HG", "HXT" },
                    // Single Bonds
                    { { "N", "CA" },
                      { "N", "H" },
                      { "N", "H2" },
                      { "CA", "C" },
                      { "CA", "CB" },
                      { "CA", "HA" },
                      { "C", "OXT" },
                      { "CB", "SG" },
                      { "CB", "HB2" },
                      { "CB", "HB3" },
                      { "SG", "HG" },
                      { "OXT", "HXT" } },
                    // Double Bonds
                    { { "C", "O" } });
ResidueData ASPData("ASP",
                    // Atoms
                    { "N", "CA", "C", "O", "CB", "CG", "OD1", "OD2", "OXT", "H",
                      "H2", "HA", "HB2", "HB3", "HD2", "HXT" },
                    // Single Bonds
                    { { "N", "CA" },
                      { "N", "H" },
                      { "N", "H2" },
                      { "CA", "C" },
                      { "CA", "CB" },
                      { "CA", "HA" },
                      { "C", "OXT" },
                      { "CB", "CG" },
                      { "CB", "HB2" },
                      { "CB", "HB3" },
                      { "CG", "OD2" },
                      { "OD2", "HD2" },
                      { "OXT", "HXT" } },
                    // Double Bonds
                    { { "C", "O" }, { "CG", "OD1" } });
ResidueData GLUData("GLU",
                    // Atoms
                    { "N", "CA", "C", "O", "CB", "CG", "CD", "OE1", "OE2",
                      "OXT", "H", "H2", "HA", "HB2", "HB3", "HG2", "HG3", "HE2",
                      "HXT" },
                    // Single Bonds
                    { { "N", "CA" },
                      { "N", "H" },
                      { "N", "H2" },
                      { "CA", "C" },
                      { "CA", "CB" },
                      { "CA", "HA" },
                      { "C", "OXT" },
                      { "CB", "CG" },
                      { "CB", "HB2" },
                      { "CB", "HB3" },
                      { "CG", "CD" },
                      { "CG", "HG2" },
                      { "CG", "HG3" },
                      { "CD", "OE2" },
                      { "OE2", "HE2" },
                      { "OXT", "HXT" } },
                    // Double Bonds
                    { { "C", "O" }, { "CD", "OE1" } });
ResidueData PHEData(
  "PHE",
  // Atoms
  { "N",   "CA",  "C",   "O",   "CB",  "CG", "CD1", "CD2",
    "CE1", "CE2", "CZ",  "OXT", "H",   "H2", "HA",  "HB2",
    "HB3", "HD1", "HD2", "HE1", "HE2", "HZ", "HXT" },
  // Single Bonds
  { { "N", "CA" },
    { "N", "H" },
    { "N", "H2" },
    { "CA", "C" },
    { "CA", "CB" },
    { "CA", "HA" },
    { "C", "OXT" },
    { "CB", "CG" },
    { "CB", "HB2" },
    { "CB", "HB3" },
    { "CG", "CD2" },
    { "CD1", "CE1" },
    { "CD1", "HD1" },
    { "CD2", "HD2" },
    { "CE1", "HE1" },
    { "CE2", "CZ" },
    { "CE2", "HE2" },
    { "CZ", "HZ" },
    { "OXT", "HXT" } },
  // Double Bonds
  { { "C", "O" }, { "CG", "CD1" }, { "CD2", "CE2" }, { "CE1", "CZ" } });
ResidueData GLYData("GLY",
                    // Atoms
                    { "N", "CA", "C", "O", "OXT", "H", "H2", "HA2", "HA3",
                      "HXT" },
                    // Single Bonds
                    { { "N", "CA" },
                      { "N", "H" },
                      { "N", "H2" },
                      { "CA", "C" },
                      { "CA", "HA2" },
                      { "CA", "HA3" },
                      { "C", "OXT" },
                      { "OXT", "HXT" } },
                    // Double Bonds
                    { { "C", "O" } });
ResidueData HISData("HIS",
                    // Atoms
                    { "N",   "CA",  "C",   "O",   "CB",  "CG",  "ND1",
                      "CD2", "CE1", "NE2", "OXT", "H",   "H2",  "HA",
                      "HB2", "HB3", "HD1", "HD2", "HE1", "HE2", "HXT" },
                    // Single Bonds
                    { { "N", "CA" },
                      { "N", "H" },
                      { "N", "H2" },
                      { "CA", "C" },
                      { "CA", "CB" },
                      { "CA", "HA" },
                      { "C", "OXT" },
                      { "CB", "CG" },
                      { "CB", "HB2" },
                      { "CB", "HB3" },
                      { "CG", "ND1" },
                      { "ND1", "HD1" },
                      { "CD2", "NE2" },
                      { "CD2", "HD2" },
                      { "CE1", "NE2" },
                      { "CE1", "HE1" },
                      { "NE2", "HE2" },
                      { "OXT", "HXT" } },
                    // Double Bonds
                    { { "C", "O" }, { "CG", "CD2" }, { "ND1", "CE1" } });
ResidueData ILEData(
  "ILE",
  // Atoms
  { "N",    "CA",   "C",    "O",    "CB",   "CG1",  "CG2",  "CD1",
    "OXT",  "H",    "H2",   "HA",   "HB",   "HG12", "HG13", "HG21",
    "HG22", "HG23", "HD11", "HD12", "HD13", "HXT" },
  // Single Bonds
  { { "N", "CA" },     { "N", "H" },      { "N", "H2" },     { "CA", "C" },
    { "CA", "CB" },    { "CA", "HA" },    { "C", "OXT" },    { "CB", "CG1" },
    { "CB", "CG2" },   { "CB", "HB" },    { "CG1", "CD1" },  { "CG1", "HG12" },
    { "CG1", "HG13" }, { "CG2", "HG21" }, { "CG2", "HG22" }, { "CG2", "HG23" },
    { "CD1", "HD11" }, { "CD1", "HD12" }, { "CD1", "HD13" }, { "OXT", "HXT" } },
  // Double Bonds
  { { "C", "O" } });
ResidueData LYSData(
  "LYS",
  // Atoms
  { "N",   "CA",  "C",   "O",   "CB",  "CG",  "CD",  "CE",  "NZ",
    "OXT", "H",   "H2",  "HA",  "HB2", "HB3", "HG2", "HG3", "HD2",
    "HD3", "HE2", "HE3", "HZ1", "HZ2", "HZ3", "HXT" },
  // Single Bonds
  { { "N", "CA" },   { "N", "H" },    { "N", "H2" },   { "CA", "C" },
    { "CA", "CB" },  { "CA", "HA" },  { "C", "OXT" },  { "CB", "CG" },
    { "CB", "HB2" }, { "CB", "HB3" }, { "CG", "CD" },  { "CG", "HG2" },
    { "CG", "HG3" }, { "CD", "CE" },  { "CD", "HD2" }, { "CD", "HD3" },
    { "CE", "NZ" },  { "CE", "HE2" }, { "CE", "HE3" }, { "NZ", "HZ1" },
    { "NZ", "HZ2" }, { "NZ", "HZ3" }, { "OXT", "HXT" } },
  // Double Bonds
  { { "C", "O" } });
ResidueData LEUData(
  "LEU",
  // Atoms
  { "N",    "CA",   "C",    "O",    "CB",   "CG",  "CD1", "CD2",
    "OXT",  "H",    "H2",   "HA",   "HB2",  "HB3", "HG",  "HD11",
    "HD12", "HD13", "HD21", "HD22", "HD23", "HXT" },
  // Single Bonds
  { { "N", "CA" },     { "N", "H" },      { "N", "H2" },     { "CA", "C" },
    { "CA", "CB" },    { "CA", "HA" },    { "C", "OXT" },    { "CB", "CG" },
    { "CB", "HB2" },   { "CB", "HB3" },   { "CG", "CD1" },   { "CG", "CD2" },
    { "CG", "HG" },    { "CD1", "HD11" }, { "CD1", "HD12" }, { "CD1", "HD13" },
    { "CD2", "HD21" }, { "CD2", "HD22" }, { "CD2", "HD23" }, { "OXT", "HXT" } },
  // Double Bonds
  { { "C", "O" } });
ResidueData METData("MET",
                    // Atoms
                    { "N",   "CA",  "C",   "O",   "CB",  "CG",  "SD",
                      "CE",  "OXT", "H",   "H2",  "HA",  "HB2", "HB3",
                      "HG2", "HG3", "HE1", "HE2", "HE3", "HXT" },
                    // Single Bonds
                    { { "N", "CA" },
                      { "N", "H" },
                      { "N", "H2" },
                      { "CA", "C" },
                      { "CA", "CB" },
                      { "CA", "HA" },
                      { "C", "OXT" },
                      { "CB", "CG" },
                      { "CB", "HB2" },
                      { "CB", "HB3" },
                      { "CG", "SD" },
                      { "CG", "HG2" },
                      { "CG", "HG3" },
                      { "SD", "CE" },
                      { "CE", "HE1" },
                      { "CE", "HE2" },
                      { "CE", "HE3" },
                      { "OXT", "HXT" } },
                    // Double Bonds
                    { { "C", "O" } });
ResidueData ASNData("ASN",
                    // Atoms
                    { "N", "CA", "C", "O", "CB", "CG", "OD1", "ND2", "OXT", "H",
                      "H2", "HA", "HB2", "HB3", "HD21", "HD22", "HXT" },
                    // Single Bonds
                    { { "N", "CA" },
                      { "N", "H" },
                      { "N", "H2" },
                      { "CA", "C" },
                      { "CA", "CB" },
                      { "CA", "HA" },
                      { "C", "OXT" },
                      { "CB", "CG" },
                      { "CB", "HB2" },
                      { "CB", "HB3" },
                      { "CG", "ND2" },
                      { "ND2", "HD21" },
                      { "ND2", "HD22" },
                      { "OXT", "HXT" } },
                    // Double Bonds
                    { { "C", "O" }, { "CG", "OD1" } });
ResidueData PROData("PRO",
                    // Atoms
                    { "N", "CA", "C", "O", "CB", "CG", "CD", "OXT", "H", "HA",
                      "HB2", "HB3", "HG2", "HG3", "HD2", "HD3", "HXT" },
                    // Single Bonds
                    { { "N", "CA" },
                      { "N", "CD" },
                      { "N", "H" },
                      { "CA", "C" },
                      { "CA", "CB" },
                      { "CA", "HA" },
                      { "C", "OXT" },
                      { "CB", "CG" },
                      { "CB", "HB2" },
                      { "CB", "HB3" },
                      { "CG", "CD" },
                      { "CG", "HG2" },
                      { "CG", "HG3" },
                      { "CD", "HD2" },
                      { "CD", "HD3" },
                      { "OXT", "HXT" } },
                    // Double Bonds
                    { { "C", "O" } });
ResidueData GLNData("GLN",
                    // Atoms
                    { "N",   "CA",  "C",   "O",    "CB",   "CG", "CD",
                      "OE1", "NE2", "OXT", "H",    "H2",   "HA", "HB2",
                      "HB3", "HG2", "HG3", "HE21", "HE22", "HXT" },
                    // Single Bonds
                    { { "N", "CA" },
                      { "N", "H" },
                      { "N", "H2" },
                      { "CA", "C" },
                      { "CA", "CB" },
                      { "CA", "HA" },
                      { "C", "OXT" },
                      { "CB", "CG" },
                      { "CB", "HB2" },
                      { "CB", "HB3" },
                      { "CG", "CD" },
                      { "CG", "HG2" },
                      { "CG", "HG3" },
                      { "CD", "NE2" },
                      { "NE2", "HE21" },
                      { "NE2", "HE22" },
                      { "OXT", "HXT" } },
                    // Double Bonds
                    { { "C", "O" }, { "CD", "OE1" } });
ResidueData ARGData(
  "ARG",
  // Atoms
  { "N",   "CA",  "C",   "O",  "CB",   "CG",   "CD",   "NE",   "CZ",
    "NH1", "NH2", "OXT", "H",  "H2",   "HA",   "HB2",  "HB3",  "HG2",
    "HG3", "HD2", "HD3", "HE", "HH11", "HH12", "HH21", "HH22", "HXT" },
  // Single Bonds
  { { "N", "CA" },     { "N", "H" },      { "N", "H2" },     { "CA", "C" },
    { "CA", "CB" },    { "CA", "HA" },    { "C", "OXT" },    { "CB", "CG" },
    { "CB", "HB2" },   { "CB", "HB3" },   { "CG", "CD" },    { "CG", "HG2" },
    { "CG", "HG3" },   { "CD", "NE" },    { "CD", "HD2" },   { "CD", "HD3" },
    { "NE", "CZ" },    { "NE", "HE" },    { "CZ", "NH1" },   { "NH1", "HH11" },
    { "NH1", "HH12" }, { "NH2", "HH21" }, { "NH2", "HH22" }, { "OXT", "HXT" } },
  // Double Bonds
  { { "C", "O" }, { "CZ", "NH2" } });
ResidueData SERData("SER",
                    // Atoms
                    { "N", "CA", "C", "O", "CB", "OG", "OXT", "H", "H2", "HA",
                      "HB2", "HB3", "HG", "HXT" },
                    // Single Bonds
                    { { "N", "CA" },
                      { "N", "H" },
                      { "N", "H2" },
                      { "CA", "C" },
                      { "CA", "CB" },
                      { "CA", "HA" },
                      { "C", "OXT" },
                      { "CB", "OG" },
                      { "CB", "HB2" },
                      { "CB", "HB3" },
                      { "OG", "HG" },
                      { "OXT", "HXT" } },
                    // Double Bonds
                    { { "C", "O" } });
ResidueData THRData("THR",
                    // Atoms
                    { "N", "CA", "C", "O", "CB", "OG1", "CG2", "OXT", "H", "H2",
                      "HA", "HB", "HG1", "HG21", "HG22", "HG23", "HXT" },
                    // Single Bonds
                    { { "N", "CA" },
                      { "N", "H" },
                      { "N", "H2" },
                      { "CA", "C" },
                      { "CA", "CB" },
                      { "CA", "HA" },
                      { "C", "OXT" },
                      { "CB", "OG1" },
                      { "CB", "CG2" },
                      { "CB", "HB" },
                      { "OG1", "HG1" },
                      { "CG2", "HG21" },
                      { "CG2", "HG22" },
                      { "CG2", "HG23" },
                      { "OXT", "HXT" } },
                    // Double Bonds
                    { { "C", "O" } });
ResidueData VALData("VAL",
                    // Atoms
                    { "N", "CA", "C", "O", "CB", "CG1", "CG2", "OXT", "H", "H2",
                      "HA", "HB", "HG11", "HG12", "HG13", "HG21", "HG22",
                      "HG23", "HXT" },
                    // Single Bonds
                    { { "N", "CA" },
                      { "N", "H" },
                      { "N", "H2" },
                      { "CA", "C" },
                      { "CA", "CB" },
                      { "CA", "HA" },
                      { "C", "OXT" },
                      { "CB", "CG1" },
                      { "CB", "CG2" },
                      { "CB", "HB" },
                      { "CG1", "HG11" },
                      { "CG1", "HG12" },
                      { "CG1", "HG13" },
                      { "CG2", "HG21" },
                      { "CG2", "HG22" },
                      { "CG2", "HG23" },
                      { "OXT", "HXT" } },
                    // Double Bonds
                    { { "C", "O" } });
ResidueData TRPData(
  "TRP",
  // Atoms
  { "N",   "CA",  "C",   "O",   "CB",  "CG",  "CD1", "CD2", "NE1",
    "CE2", "CE3", "CZ2", "CZ3", "CH2", "OXT", "H",   "H2",  "HA",
    "HB2", "HB3", "HD1", "HE1", "HE3", "HZ2", "HZ3", "HH2", "HXT" },
  // Single Bonds
  { { "N", "CA" },    { "N", "H" },     { "N", "H2" },    { "CA", "C" },
    { "CA", "CB" },   { "CA", "HA" },   { "C", "OXT" },   { "CB", "CG" },
    { "CB", "HB2" },  { "CB", "HB3" },  { "CG", "CD2" },  { "CD1", "NE1" },
    { "CD1", "HD1" }, { "CD2", "CE3" }, { "NE1", "CE2" }, { "NE1", "HE1" },
    { "CE2", "CZ2" }, { "CE3", "HE3" }, { "CZ2", "HZ2" }, { "CZ3", "CH2" },
    { "CZ3", "HZ3" }, { "CH2", "HH2" }, { "OXT", "HXT" } },
  // Double Bonds
  { { "C", "O" },
    { "CG", "CD1" },
    { "CD2", "CE2" },
    { "CE3", "CZ3" },
    { "CZ2", "CH2" } });
ResidueData TYRData(
  "TYR",
  // Atoms
  { "N",   "CA",  "C",   "O",   "CB",  "CG",  "CD1", "CD2",
    "CE1", "CE2", "CZ",  "OH",  "OXT", "H",   "H2",  "HA",
    "HB2", "HB3", "HD1", "HD2", "HE1", "HE2", "HH",  "HXT" },
  // Single Bonds
  { { "N", "CA" },    { "N", "H" },     { "N", "H2" },    { "CA", "C" },
    { "CA", "CB" },   { "CA", "HA" },   { "C", "OXT" },   { "CB", "CG" },
    { "CB", "HB2" },  { "CB", "HB3" },  { "CG", "CD2" },  { "CD1", "CE1" },
    { "CD1", "HD1" }, { "CD2", "HD2" }, { "CE1", "HE1" }, { "CE2", "CZ" },
    { "CE2", "HE2" }, { "CZ", "OH" },   { "OH", "HH" },   { "OXT", "HXT" } },
  // Double Bonds
  { { "C", "O" }, { "CG", "CD1" }, { "CD2", "CE2" }, { "CE1", "CZ" } });
ResidueData DAData(
  "DA",
  // Atoms
  { "OP3", "P",    "OP1", "OP2",  "O5'",  "C5'",  "C4'", "O4'",  "C3'",
    "O3'", "C2'",  "C1'", "N9",   "C8",   "N7",   "C5",  "C6",   "N6",
    "N1",  "C2",   "N3",  "C4",   "HOP3", "HOP2", "H5'", "H5''", "H4'",
    "H3'", "HO3'", "H2'", "H2''", "H1'",  "H8",   "H61", "H62",  "H2" },
  // Single Bonds
  { { "OP3", "P" },    { "OP3", "HOP3" }, { "P", "OP2" },   { "P", "O5'" },
    { "OP2", "HOP2" }, { "O5'", "C5'" },  { "C5'", "C4'" }, { "C5'", "H5'" },
    { "C5'", "H5''" }, { "C4'", "O4'" },  { "C4'", "C3'" }, { "C4'", "H4'" },
    { "O4'", "C1'" },  { "C3'", "O3'" },  { "C3'", "C2'" }, { "C3'", "H3'" },
    { "O3'", "HO3'" }, { "C2'", "C1'" },  { "C2'", "H2'" }, { "C2'", "H2''" },
    { "C1'", "N9" },   { "C1'", "H1'" },  { "N9", "C8" },   { "N9", "C4" },
    { "C8", "H8" },    { "N7", "C5" },    { "C5", "C6" },   { "C6", "N6" },
    { "N6", "H61" },   { "N6", "H62" },   { "N1", "C2" },   { "C2", "H2" },
    { "N3", "C4" } },
  // Double Bonds
  { { "P", "OP1" },
    { "C8", "N7" },
    { "C5", "C4" },
    { "C6", "N1" },
    { "C2", "N3" } });
ResidueData DCData(
  "DC",
  // Atoms
  { "OP3", "P",    "OP1",  "OP2",  "O5'", "C5'",  "C4'", "O4'", "C3'",
    "O3'", "C2'",  "C1'",  "N1",   "C2",  "O2",   "N3",  "C4",  "N4",
    "C5",  "C6",   "HOP3", "HOP2", "H5'", "H5''", "H4'", "H3'", "HO3'",
    "H2'", "H2''", "H1'",  "H41",  "H42", "H5",   "H6" },
  // Single Bonds
  { { "OP3", "P" },    { "OP3", "HOP3" }, { "P", "OP2" },   { "P", "O5'" },
    { "OP2", "HOP2" }, { "O5'", "C5'" },  { "C5'", "C4'" }, { "C5'", "H5'" },
    { "C5'", "H5''" }, { "C4'", "O4'" },  { "C4'", "C3'" }, { "C4'", "H4'" },
    { "O4'", "C1'" },  { "C3'", "O3'" },  { "C3'", "C2'" }, { "C3'", "H3'" },
    { "O3'", "HO3'" }, { "C2'", "C1'" },  { "C2'", "H2'" }, { "C2'", "H2''" },
    { "C1'", "N1" },   { "C1'", "H1'" },  { "N1", "C2" },   { "N1", "C6" },
    { "C2", "N3" },    { "C4", "N4" },    { "C4", "C5" },   { "N4", "H41" },
    { "N4", "H42" },   { "C5", "H5" },    { "C6", "H6" } },
  // Double Bonds
  { { "P", "OP1" }, { "C2", "O2" }, { "N3", "C4" }, { "C5", "C6" } });
ResidueData DGData(
  "DG",
  // Atoms
  { "OP3", "P",    "OP1", "OP2",  "O5'",  "C5'", "C4'",  "O4'", "C3'", "O3'",
    "C2'", "C1'",  "N9",  "C8",   "N7",   "C5",  "C6",   "O6",  "N1",  "C2",
    "N2",  "N3",   "C4",  "HOP3", "HOP2", "H5'", "H5''", "H4'", "H3'", "HO3'",
    "H2'", "H2''", "H1'", "H8",   "H1",   "H21", "H22" },
  // Single Bonds
  { { "OP3", "P" },    { "OP3", "HOP3" }, { "P", "OP2" },   { "P", "O5'" },
    { "OP2", "HOP2" }, { "O5'", "C5'" },  { "C5'", "C4'" }, { "C5'", "H5'" },
    { "C5'", "H5''" }, { "C4'", "O4'" },  { "C4'", "C3'" }, { "C4'", "H4'" },
    { "O4'", "C1'" },  { "C3'", "O3'" },  { "C3'", "C2'" }, { "C3'", "H3'" },
    { "O3'", "HO3'" }, { "C2'", "C1'" },  { "C2'", "H2'" }, { "C2'", "H2''" },
    { "C1'", "N9" },   { "C1'", "H1'" },  { "N9", "C8" },   { "N9", "C4" },
    { "C8", "H8" },    { "N7", "C5" },    { "C5", "C6" },   { "C6", "N1" },
    { "N1", "C2" },    { "N1", "H1" },    { "C2", "N2" },   { "N2", "H21" },
    { "N2", "H22" },   { "N3", "C4" } },
  // Double Bonds
  { { "P", "OP1" },
    { "C8", "N7" },
    { "C5", "C4" },
    { "C6", "O6" },
    { "C2", "N3" } });
ResidueData DTData(
  "DT",
  // Atoms
  { "OP3",  "P",   "OP1",  "OP2",  "O5'",  "C5'", "C4'",  "O4'", "C3'",
    "O3'",  "C2'", "C1'",  "N1",   "C2",   "O2",  "N3",   "C4",  "O4",
    "C5",   "C7",  "C6",   "HOP3", "HOP2", "H5'", "H5''", "H4'", "H3'",
    "HO3'", "H2'", "H2''", "H1'",  "H3",   "H71", "H72",  "H73", "H6" },
  // Single Bonds
  { { "OP3", "P" },    { "OP3", "HOP3" }, { "P", "OP2" },   { "P", "O5'" },
    { "OP2", "HOP2" }, { "O5'", "C5'" },  { "C5'", "C4'" }, { "C5'", "H5'" },
    { "C5'", "H5''" }, { "C4'", "O4'" },  { "C4'", "C3'" }, { "C4'", "H4'" },
    { "O4'", "C1'" },  { "C3'", "O3'" },  { "C3'", "C2'" }, { "C3'", "H3'" },
    { "O3'", "HO3'" }, { "C2'", "C1'" },  { "C2'", "H2'" }, { "C2'", "H2''" },
    { "C1'", "N1" },   { "C1'", "H1'" },  { "N1", "C2" },   { "N1", "C6" },
    { "C2", "N3" },    { "N3", "C4" },    { "N3", "H3" },   { "C4", "C5" },
    { "C5", "C7" },    { "C7", "H71" },   { "C7", "H72" },  { "C7", "H73" },
    { "C6", "H6" } },
  // Double Bonds
  { { "P", "OP1" }, { "C2", "O2" }, { "C4", "O4" }, { "C5", "C6" } });
ResidueData DIData(
  "DI",
  // Atoms
  { "OP3", "P",    "OP1", "OP2",  "O5'",  "C5'",  "C4'", "O4'",  "C3'",
    "O3'", "C2'",  "C1'", "N9",   "C8",   "N7",   "C5",  "C6",   "O6",
    "N1",  "C2",   "N3",  "C4",   "HOP3", "HOP2", "H5'", "H5''", "H4'",
    "H3'", "HO3'", "H2'", "H2''", "H1'",  "H8",   "H1",  "H2" },
  // Single Bonds
  { { "OP3", "P" },    { "OP3", "HOP3" }, { "P", "OP2" },   { "P", "O5'" },
    { "OP2", "HOP2" }, { "O5'", "C5'" },  { "C5'", "C4'" }, { "C5'", "H5'" },
    { "C5'", "H5''" }, { "C4'", "O4'" },  { "C4'", "C3'" }, { "C4'", "H4'" },
    { "O4'", "C1'" },  { "C3'", "O3'" },  { "C3'", "C2'" }, { "C3'", "H3'" },
    { "O3'", "HO3'" }, { "C2'", "C1'" },  { "C2'", "H2'" }, { "C2'", "H2''" },
    { "C1'", "N9" },   { "C1'", "H1'" },  { "N9", "C8" },   { "N9", "C4" },
    { "C8", "H8" },    { "N7", "C5" },    { "C5", "C6" },   { "C6", "N1" },
    { "N1", "C2" },    { "N1", "H1" },    { "C2", "H2" },   { "N3", "C4" } },
  // Double Bonds
  { { "P", "OP1" },
    { "C8", "N7" },
    { "C5", "C4" },
    { "C6", "O6" },
    { "C2", "N3" } });
ResidueData AData(
  "A",
  // Atoms
  { "OP3", "P",    "OP1", "OP2",  "O5'",  "C5'", "C4'",  "O4'", "C3'", "O3'",
    "C2'", "O2'",  "C1'", "N9",   "C8",   "N7",  "C5",   "C6",  "N6",  "N1",
    "C2",  "N3",   "C4",  "HOP3", "HOP2", "H5'", "H5''", "H4'", "H3'", "HO3'",
    "H2'", "HO2'", "H1'", "H8",   "H61",  "H62", "H2" },
  // Single Bonds
  { { "OP3", "P" },    { "OP3", "HOP3" }, { "P", "OP2" },   { "P", "O5'" },
    { "OP2", "HOP2" }, { "O5'", "C5'" },  { "C5'", "C4'" }, { "C5'", "H5'" },
    { "C5'", "H5''" }, { "C4'", "O4'" },  { "C4'", "C3'" }, { "C4'", "H4'" },
    { "O4'", "C1'" },  { "C3'", "O3'" },  { "C3'", "C2'" }, { "C3'", "H3'" },
    { "O3'", "HO3'" }, { "C2'", "O2'" },  { "C2'", "C1'" }, { "C2'", "H2'" },
    { "O2'", "HO2'" }, { "C1'", "N9" },   { "C1'", "H1'" }, { "N9", "C8" },
    { "N9", "C4" },    { "C8", "H8" },    { "N7", "C5" },   { "C5", "C6" },
    { "C6", "N6" },    { "N6", "H61" },   { "N6", "H62" },  { "N1", "C2" },
    { "C2", "H2" },    { "N3", "C4" } },
  // Double Bonds
  { { "P", "OP1" },
    { "C8", "N7" },
    { "C5", "C4" },
    { "C6", "N1" },
    { "C2", "N3" } });
ResidueData CData(
  "C",
  // Atoms
  { "OP3",  "P",   "OP1",  "OP2",  "O5'",  "C5'", "C4'",  "O4'", "C3'",
    "O3'",  "C2'", "O2'",  "C1'",  "N1",   "C2",  "O2",   "N3",  "C4",
    "N4",   "C5",  "C6",   "HOP3", "HOP2", "H5'", "H5''", "H4'", "H3'",
    "HO3'", "H2'", "HO2'", "H1'",  "H41",  "H42", "H5",   "H6" },
  // Single Bonds
  { { "OP3", "P" },    { "OP3", "HOP3" }, { "P", "OP2" },   { "P", "O5'" },
    { "OP2", "HOP2" }, { "O5'", "C5'" },  { "C5'", "C4'" }, { "C5'", "H5'" },
    { "C5'", "H5''" }, { "C4'", "O4'" },  { "C4'", "C3'" }, { "C4'", "H4'" },
    { "O4'", "C1'" },  { "C3'", "O3'" },  { "C3'", "C2'" }, { "C3'", "H3'" },
    { "O3'", "HO3'" }, { "C2'", "O2'" },  { "C2'", "C1'" }, { "C2'", "H2'" },
    { "O2'", "HO2'" }, { "C1'", "N1" },   { "C1'", "H1'" }, { "N1", "C2" },
    { "N1", "C6" },    { "C2", "N3" },    { "C4", "N4" },   { "C4", "C5" },
    { "N4", "H41" },   { "N4", "H42" },   { "C5", "H5" },   { "C6", "H6" } },
  // Double Bonds
  { { "P", "OP1" }, { "C2", "O2" }, { "N3", "C4" }, { "C5", "C6" } });
ResidueData GData(
  "G",
  // Atoms
  { "OP3",  "P",   "OP1",  "OP2", "O5'",  "C5'",  "C4'", "O4'",  "C3'", "O3'",
    "C2'",  "O2'", "C1'",  "N9",  "C8",   "N7",   "C5",  "C6",   "O6",  "N1",
    "C2",   "N2",  "N3",   "C4",  "HOP3", "HOP2", "H5'", "H5''", "H4'", "H3'",
    "HO3'", "H2'", "HO2'", "H1'", "H8",   "H1",   "H21", "H22" },
  // Single Bonds
  { { "OP3", "P" },    { "OP3", "HOP3" }, { "P", "OP2" },   { "P", "O5'" },
    { "OP2", "HOP2" }, { "O5'", "C5'" },  { "C5'", "C4'" }, { "C5'", "H5'" },
    { "C5'", "H5''" }, { "C4'", "O4'" },  { "C4'", "C3'" }, { "C4'", "H4'" },
    { "O4'", "C1'" },  { "C3'", "O3'" },  { "C3'", "C2'" }, { "C3'", "H3'" },
    { "O3'", "HO3'" }, { "C2'", "O2'" },  { "C2'", "C1'" }, { "C2'", "H2'" },
    { "O2'", "HO2'" }, { "C1'", "N9" },   { "C1'", "H1'" }, { "N9", "C8" },
    { "N9", "C4" },    { "C8", "H8" },    { "N7", "C5" },   { "C5", "C6" },
    { "C6", "N1" },    { "N1", "C2" },    { "N1", "H1" },   { "C2", "N2" },
    { "N2", "H21" },   { "N2", "H22" },   { "N3", "C4" } },
  // Double Bonds
  { { "P", "OP1" },
    { "C8", "N7" },
    { "C5", "C4" },
    { "C6", "O6" },
    { "C2", "N3" } });
ResidueData UData(
  "U",
  // Atoms
  { "OP3",  "P",   "OP1",  "OP2",  "O5'",  "C5'", "C4'",  "O4'", "C3'",
    "O3'",  "C2'", "O2'",  "C1'",  "N1",   "C2",  "O2",   "N3",  "C4",
    "O4",   "C5",  "C6",   "HOP3", "HOP2", "H5'", "H5''", "H4'", "H3'",
    "HO3'", "H2'", "HO2'", "H1'",  "H3",   "H5",  "H6" },
  // Single Bonds
  { { "OP3", "P" },    { "OP3", "HOP3" }, { "P", "OP2" },   { "P", "O5'" },
    { "OP2", "HOP2" }, { "O5'", "C5'" },  { "C5'", "C4'" }, { "C5'", "H5'" },
    { "C5'", "H5''" }, { "C4'", "O4'" },  { "C4'", "C3'" }, { "C4'", "H4'" },
    { "O4'", "C1'" },  { "C3'", "O3'" },  { "C3'", "C2'" }, { "C3'", "H3'" },
    { "O3'", "HO3'" }, { "C2'", "O2'" },  { "C2'", "C1'" }, { "C2'", "H2'" },
    { "O2'", "HO2'" }, { "C1'", "N1" },   { "C1'", "H1'" }, { "N1", "C2" },
    { "N1", "C6" },    { "C2", "N3" },    { "N3", "C4" },   { "N3", "H3" },
    { "C4", "C5" },    { "C5", "H5" },    { "C6", "H6" } },
  // Double Bonds
  { { "P", "OP1" }, { "C2", "O2" }, { "C4", "O4" }, { "C5", "C6" } });
ResidueData IData(
  "I",
  // Atoms
  { "OP3", "P",   "OP1",  "OP2", "O5'",  "C5'",  "C4'",  "O4'", "C3'",
    "O3'", "C2'", "O2'",  "C1'", "N9",   "C8",   "N7",   "C5",  "C6",
    "O6",  "N1",  "C2",   "N3",  "C4",   "HOP3", "HOP2", "H5'", "H5''",
    "H4'", "H3'", "HO3'", "H2'", "HO2'", "H1'",  "H8",   "H1",  "H2" },
  // Single Bonds
  { { "OP3", "P" },    { "OP3", "HOP3" }, { "P", "OP2" },   { "P", "O5'" },
    { "OP2", "HOP2" }, { "O5'", "C5'" },  { "C5'", "C4'" }, { "C5'", "H5'" },
    { "C5'", "H5''" }, { "C4'", "O4'" },  { "C4'", "C3'" }, { "C4'", "H4'" },
    { "O4'", "C1'" },  { "C3'", "O3'" },  { "C3'", "C2'" }, { "C3'", "H3'" },
    { "O3'", "HO3'" }, { "C2'", "O2'" },  { "C2'", "C1'" }, { "C2'", "H2'" },
    { "O2'", "HO2'" }, { "C1'", "N9" },   { "C1'", "H1'" }, { "N9", "C8" },
    { "N9", "C4" },    { "C8", "H8" },    { "N7", "C5" },   { "C5", "C6" },
    { "C6", "N1" },    { "N1", "C2" },    { "N1", "H1" },   { "C2", "H2" },
    { "N3", "C4" } },
  // Double Bonds
  { { "P", "OP1" },
    { "C8", "N7" },
    { "C5", "C4" },
    { "C6", "O6" },
    { "C2", "N3" } });
ResidueData HEMData(
  "HEM",
  // Atoms
  { "CHA",  "CHB",  "CHC",  "CHD",  "C1A",  "C2A",  "C3A",  "C4A",  "CMA",
    "CAA",  "CBA",  "CGA",  "O1A",  "O2A",  "C1B",  "C2B",  "C3B",  "C4B",
    "CMB",  "CAB",  "CBB",  "C1C",  "C2C",  "C3C",  "C4C",  "CMC",  "CAC",
    "CBC",  "C1D",  "C2D",  "C3D",  "C4D",  "CMD",  "CAD",  "CBD",  "CGD",
    "O1D",  "O2D",  "NA",   "NB",   "NC",   "ND",   "FE",   "HHB",  "HHC",
    "HHD",  "HMA",  "HMAA", "HMAB", "HAA",  "HAAA", "HBA",  "HBAA", "HMB",
    "HMBA", "HMBB", "HAB",  "HBB",  "HBBA", "HMC",  "HMCA", "HMCB", "HAC",
    "HBC",  "HBCA", "HMD",  "HMDA", "HMDB", "HAD",  "HADA", "HBD",  "HBDA",
    "H2A",  "H2D",  "HHA" },
  // Single Bonds
  { { "CHA", "C1A" },  { "CHA", "HHA" },  { "CHB", "C4A" },  { "CHB", "HHB" },
    { "CHC", "C4B" },  { "CHC", "HHC" },  { "CHD", "C1D" },  { "CHD", "HHD" },
    { "C1A", "NA" },   { "C2A", "C3A" },  { "C2A", "CAA" },  { "C3A", "CMA" },
    { "C4A", "NA" },   { "CMA", "HMA" },  { "CMA", "HMAA" }, { "CMA", "HMAB" },
    { "CAA", "CBA" },  { "CAA", "HAA" },  { "CAA", "HAAA" }, { "CBA", "CGA" },
    { "CBA", "HBA" },  { "CBA", "HBAA" }, { "CGA", "O2A" },  { "O2A", "H2A" },
    { "C1B", "C2B" },  { "C1B", "NB" },   { "C2B", "CMB" },  { "C3B", "C4B" },
    { "C3B", "CAB" },  { "CMB", "HMB" },  { "CMB", "HMBA" }, { "CMB", "HMBB" },
    { "CAB", "HAB" },  { "CBB", "HBB" },  { "CBB", "HBBA" }, { "C1C", "C2C" },
    { "C1C", "NC" },   { "C2C", "CMC" },  { "C3C", "C4C" },  { "C3C", "CAC" },
    { "C4C", "NC" },   { "CMC", "HMC" },  { "CMC", "HMCA" }, { "CMC", "HMCB" },
    { "CAC", "HAC" },  { "CBC", "HBC" },  { "CBC", "HBCA" }, { "C1D", "C2D" },
    { "C2D", "CMD" },  { "C3D", "C4D" },  { "C3D", "CAD" },  { "C4D", "ND" },
    { "CMD", "HMD" },  { "CMD", "HMDA" }, { "CMD", "HMDB" }, { "CAD", "CBD" },
    { "CAD", "HAD" },  { "CAD", "HADA" }, { "CBD", "CGD" },  { "CBD", "HBD" },
    { "CBD", "HBDA" }, { "CGD", "O2D" },  { "O2D", "H2D" },  { "FE", "NA" },
    { "FE", "NB" },    { "FE", "NC" },    { "FE", "ND" } },
  // Double Bonds
  { { "CHA", "C4D" },
    { "CHB", "C1B" },
    { "CHC", "C1C" },
    { "CHD", "C4C" },
    { "C1A", "C2A" },
    { "C3A", "C4A" },
    { "CGA", "O1A" },
    { "C2B", "C3B" },
    { "C4B", "NB" },
    { "CAB", "CBB" },
    { "C2C", "C3C" },
    { "CAC", "CBC" },
    { "C1D", "ND" },
    { "C2D", "C3D" },
    { "CGD", "O1D" } });
ResidueData HOHData("HOH",
                    // Atoms
                    { "O", "H1", "H2" },
                    // Single Bonds
                    { { "O", "H1" }, { "O", "H2" } },
                    // Double Bonds
                    {});
ResidueData SO4Data("SO4",
                    // Atoms
                    { "S", "O1", "O2", "O3", "O4" },
                    // Single Bonds
                    { { "S", "O3" }, { "S", "O4" } },
                    // Double Bonds
                    { { "S", "O1" }, { "S", "O2" } });
ResidueData GOLData("GOL",
                    // Atoms
                    { "C1", "O1", "C2", "O2", "C3", "O3", "H11", "H12", "HO1",
                      "H2", "HO2", "H31", "H32", "HO3" },
                    // Single Bonds
                    { { "C1", "O1" },
                      { "C1", "C2" },
                      { "C1", "H11" },
                      { "C1", "H12" },
                      { "O1", "HO1" },
                      { "C2", "O2" },
                      { "C2", "C3" },
                      { "C2", "H2" },
                      { "O2", "HO2" },
                      { "C3", "O3" },
                      { "C3", "H31" },
                      { "C3", "H32" },
                      { "O3", "HO3" } },
                    // Double Bonds
                    {});
ResidueData MSEData("MSE",
                    // Atoms
                    { "N",   "CA",  "C",   "O",   "OXT", "CB",  "CG",
                      "SE",  "CE",  "H",   "HN2", "HA",  "HXT", "HB2",
                      "HB3", "HG2", "HG3", "HE1", "HE2", "HE3" },
                    // Single Bonds
                    { { "N", "CA" },
                      { "N", "H" },
                      { "N", "HN2" },
                      { "CA", "C" },
                      { "CA", "CB" },
                      { "CA", "HA" },
                      { "C", "OXT" },
                      { "OXT", "HXT" },
                      { "CB", "CG" },
                      { "CB", "HB2" },
                      { "CB", "HB3" },
                      { "CG", "SE" },
                      { "CG", "HG2" },
                      { "CG", "HG3" },
                      { "SE", "CE" },
                      { "CE", "HE1" },
                      { "CE", "HE2" },
                      { "CE", "HE3" } },
                    // Double Bonds
                    { { "C", "O" } });
ResidueData EDOData("EDO",
                    // Atoms
                    { "C1", "O1", "C2", "O2", "H11", "H12", "HO1", "H21", "H22",
                      "HO2" },
                    // Single Bonds
                    { { "C1", "O1" },
                      { "C1", "C2" },
                      { "C1", "H11" },
                      { "C1", "H12" },
                      { "O1", "HO1" },
                      { "C2", "O2" },
                      { "C2", "H21" },
                      { "C2", "H22" },
                      { "O2", "HO2" } },
                    // Double Bonds
                    {});
ResidueData NAGData(
  "NAG",
  // Atoms
  { "C1",  "C2",  "C3",  "C4",  "C5",  "C6",  "C7",  "C8",  "N2",  "O1",
    "O3",  "O4",  "O5",  "O6",  "O7",  "H1",  "H2",  "H3",  "H4",  "H5",
    "H61", "H62", "H81", "H82", "H83", "HN2", "HO1", "HO3", "HO4", "HO6" },
  // Single Bonds
  { { "C1", "C2" },  { "C1", "O1" },  { "C1", "O5" },  { "C1", "H1" },
    { "C2", "C3" },  { "C2", "N2" },  { "C2", "H2" },  { "C3", "C4" },
    { "C3", "O3" },  { "C3", "H3" },  { "C4", "C5" },  { "C4", "O4" },
    { "C4", "H4" },  { "C5", "C6" },  { "C5", "O5" },  { "C5", "H5" },
    { "C6", "O6" },  { "C6", "H61" }, { "C6", "H62" }, { "C7", "C8" },
    { "C7", "N2" },  { "C8", "H81" }, { "C8", "H82" }, { "C8", "H83" },
    { "N2", "HN2" }, { "O1", "HO1" }, { "O3", "HO3" }, { "O4", "HO4" },
    { "O6", "HO6" } },
  // Double Bonds
  { { "C7", "O7" } });
ResidueData PO4Data("PO4",
                    // Atoms
                    { "P", "O1", "O2", "O3", "O4" },
                    // Single Bonds
                    { { "P", "O2" }, { "P", "O3" }, { "P", "O4" } },
                    // Double Bonds
                    { { "P", "O1" } });
ResidueData ACTData("ACT",
                    // Atoms
                    { "C", "O", "OXT", "CH3", "H1", "H2", "H3" },
                    // Single Bonds
                    { { "C", "OXT" },
                      { "C", "CH3" },
                      { "CH3", "H1" },
                      { "CH3", "H2" },
                      { "CH3", "H3" } },
                    // Double Bonds
                    { { "C", "O" } });
ResidueData PEGData("PEG",
                    // Atoms
                    { "C1", "O1", "C2", "O2", "C3", "C4", "O4", "H11", "H12",
                      "HO1", "H21", "H22", "H31", "H32", "H41", "H42", "HO4" },
                    // Single Bonds
                    { { "C1", "O1" },
                      { "C1", "C2" },
                      { "C1", "H11" },
                      { "C1", "H12" },
                      { "O1", "HO1" },
                      { "C2", "O2" },
                      { "C2", "H21" },
                      { "C2", "H22" },
                      { "O2", "C3" },
                      { "C3", "C4" },
                      { "C3", "H31" },
                      { "C3", "H32" },
                      { "C4", "O4" },
                      { "C4", "H41" },
                      { "C4", "H42" },
                      { "O4", "HO4" } },
                    // Double Bonds
                    {});
ResidueData MANData("MAN",
                    // Atoms
                    { "C1", "C2",  "C3",  "C4",  "C5",  "C6",  "O1",  "O2",
                      "O3", "O4",  "O5",  "O6",  "H1",  "H2",  "H3",  "H4",
                      "H5", "H61", "H62", "HO1", "HO2", "HO3", "HO4", "HO6" },
                    // Single Bonds
                    { { "C1", "C2" },  { "C1", "O1" },  { "C1", "O5" },
                      { "C1", "H1" },  { "C2", "C3" },  { "C2", "O2" },
                      { "C2", "H2" },  { "C3", "C4" },  { "C3", "O3" },
                      { "C3", "H3" },  { "C4", "C5" },  { "C4", "O4" },
                      { "C4", "H4" },  { "C5", "C6" },  { "C5", "O5" },
                      { "C5", "H5" },  { "C6", "O6" },  { "C6", "H61" },
                      { "C6", "H62" }, { "O1", "HO1" }, { "O2", "HO2" },
                      { "O3", "HO3" }, { "O4", "HO4" }, { "O6", "HO6" } },
                    // Double Bonds
                    {});
ResidueData BMAData("BMA",
                    // Atoms
                    { "C1", "C2",  "C3",  "C4",  "C5",  "C6",  "O1",  "O2",
                      "O3", "O4",  "O5",  "O6",  "H1",  "H2",  "H3",  "H4",
                      "H5", "H61", "H62", "HO1", "HO2", "HO3", "HO4", "HO6" },
                    // Single Bonds
                    { { "C1", "C2" },  { "C1", "O1" },  { "C1", "O5" },
                      { "C1", "H1" },  { "C2", "C3" },  { "C2", "O2" },
                      { "C2", "H2" },  { "C3", "C4" },  { "C3", "O3" },
                      { "C3", "H3" },  { "C4", "C5" },  { "C4", "O4" },
                      { "C4", "H4" },  { "C5", "C6" },  { "C5", "O5" },
                      { "C5", "H5" },  { "C6", "O6" },  { "C6", "H61" },
                      { "C6", "H62" }, { "O1", "HO1" }, { "O2", "HO2" },
                      { "O3", "HO3" }, { "O4", "HO4" }, { "O6", "HO6" } },
                    // Double Bonds
                    {});
ResidueData FADData(
  "FAD",
  // Atoms
  { "PA",   "O1A",  "O2A",  "O5B",  "C5B",  "C4B",  "O4B",  "C3B",  "O3B",
    "C2B",  "O2B",  "C1B",  "N9A",  "C8A",  "N7A",  "C5A",  "C6A",  "N6A",
    "N1A",  "C2A",  "N3A",  "C4A",  "N1",   "C2",   "O2",   "N3",   "C4",
    "O4",   "C4X",  "N5",   "C5X",  "C6",   "C7",   "C7M",  "C8",   "C8M",
    "C9",   "C9A",  "N10",  "C10",  "C1'",  "C2'",  "O2'",  "C3'",  "O3'",
    "C4'",  "O4'",  "C5'",  "O5'",  "P",    "O1P",  "O2P",  "O3P",  "HOA2",
    "H51A", "H52A", "H4B",  "H3B",  "HO3A", "H2B",  "HO2A", "H1B",  "H8A",
    "H61A", "H62A", "H2A",  "HN3",  "H6",   "HM71", "HM72", "HM73", "HM81",
    "HM82", "HM83", "H9",   "H1'1", "H1'2", "H2'",  "HO2'", "H3'",  "HO3'",
    "H4'",  "HO4'", "H5'1", "H5'2", "HOP2" },
  // Single Bonds
  { { "PA", "O2A" },   { "PA", "O5B" },   { "PA", "O3P" },   { "O2A", "HOA2" },
    { "O5B", "C5B" },  { "C5B", "C4B" },  { "C5B", "H51A" }, { "C5B", "H52A" },
    { "C4B", "O4B" },  { "C4B", "C3B" },  { "C4B", "H4B" },  { "O4B", "C1B" },
    { "C3B", "O3B" },  { "C3B", "C2B" },  { "C3B", "H3B" },  { "O3B", "HO3A" },
    { "C2B", "O2B" },  { "C2B", "C1B" },  { "C2B", "H2B" },  { "O2B", "HO2A" },
    { "C1B", "N9A" },  { "C1B", "H1B" },  { "N9A", "C8A" },  { "N9A", "C4A" },
    { "C8A", "H8A" },  { "N7A", "C5A" },  { "C5A", "C6A" },  { "C6A", "N6A" },
    { "N6A", "H61A" }, { "N6A", "H62A" }, { "N1A", "C2A" },  { "C2A", "H2A" },
    { "N3A", "C4A" },  { "N1", "C2" },    { "C2", "N3" },    { "N3", "C4" },
    { "N3", "HN3" },   { "C4", "C4X" },   { "C4X", "C10" },  { "N5", "C5X" },
    { "C5X", "C9A" },  { "C6", "C7" },    { "C6", "H6" },    { "C7", "C7M" },
    { "C7M", "HM71" }, { "C7M", "HM72" }, { "C7M", "HM73" }, { "C8", "C8M" },
    { "C8", "C9" },    { "C8M", "HM81" }, { "C8M", "HM82" }, { "C8M", "HM83" },
    { "C9", "H9" },    { "C9A", "N10" },  { "N10", "C10" },  { "N10", "C1'" },
    { "C1'", "C2'" },  { "C1'", "H1'1" }, { "C1'", "H1'2" }, { "C2'", "O2'" },
    { "C2'", "C3'" },  { "C2'", "H2'" },  { "O2'", "HO2'" }, { "C3'", "O3'" },
    { "C3'", "C4'" },  { "C3'", "H3'" },  { "O3'", "HO3'" }, { "C4'", "O4'" },
    { "C4'", "C5'" },  { "C4'", "H4'" },  { "O4'", "HO4'" }, { "C5'", "O5'" },
    { "C5'", "H5'1" }, { "C5'", "H5'2" }, { "O5'", "P" },    { "P", "O2P" },
    { "P", "O3P" },    { "O2P", "HOP2" } },
  // Double Bonds
  { { "PA", "O1A" },
    { "C8A", "N7A" },
    { "C5A", "C4A" },
    { "C6A", "N1A" },
    { "C2A", "N3A" },
    { "N1", "C10" },
    { "C2", "O2" },
    { "C4", "O4" },
    { "C4X", "N5" },
    { "C5X", "C6" },
    { "C7", "C8" },
    { "C9", "C9A" },
    { "P", "O1P" } });
ResidueData ADPData(
  "ADP",
  // Atoms
  { "PB",   "O1B",  "O2B",  "O3B",  "PA",   "O1A", "O2A", "O3A",  "O5'",
    "C5'",  "C4'",  "O4'",  "C3'",  "O3'",  "C2'", "O2'", "C1'",  "N9",
    "C8",   "N7",   "C5",   "C6",   "N6",   "N1",  "C2",  "N3",   "C4",
    "HOB2", "HOB3", "HOA2", "H5'1", "H5'2", "H4'", "H3'", "HO3'", "H2'",
    "HO2'", "H1'",  "H8",   "HN61", "HN62", "H2" },
  // Single Bonds
  { { "PB", "O2B" },   { "PB", "O3B" },  { "PB", "O3A" },  { "O2B", "HOB2" },
    { "O3B", "HOB3" }, { "PA", "O2A" },  { "PA", "O3A" },  { "PA", "O5'" },
    { "O2A", "HOA2" }, { "O5'", "C5'" }, { "C5'", "C4'" }, { "C5'", "H5'1" },
    { "C5'", "H5'2" }, { "C4'", "O4'" }, { "C4'", "C3'" }, { "C4'", "H4'" },
    { "O4'", "C1'" },  { "C3'", "O3'" }, { "C3'", "C2'" }, { "C3'", "H3'" },
    { "O3'", "HO3'" }, { "C2'", "O2'" }, { "C2'", "C1'" }, { "C2'", "H2'" },
    { "O2'", "HO2'" }, { "C1'", "N9" },  { "C1'", "H1'" }, { "N9", "C8" },
    { "N9", "C4" },    { "C8", "H8" },   { "N7", "C5" },   { "C5", "C6" },
    { "C6", "N6" },    { "N6", "HN61" }, { "N6", "HN62" }, { "N1", "C2" },
    { "C2", "H2" },    { "N3", "C4" } },
  // Double Bonds
  { { "PB", "O1B" },
    { "PA", "O1A" },
    { "C8", "N7" },
    { "C5", "C4" },
    { "C6", "N1" },
    { "C2", "N3" } });
ResidueData DMSData("DMS",
                    // Atoms
                    { "S", "O", "C1", "C2", "H11", "H12", "H13", "H21", "H22",
                      "H23" },
                    // Single Bonds
                    { { "S", "C1" },
                      { "S", "C2" },
                      { "C1", "H11" },
                      { "C1", "H12" },
                      { "C1", "H13" },
                      { "C2", "H21" },
                      { "C2", "H22" },
                      { "C2", "H23" } },
                    // Double Bonds
                    { { "S", "O" } });
ResidueData ACEData("ACE",
                    // Atoms
                    { "C", "O", "CH3", "H", "H1", "H2", "H3" },
                    // Single Bonds
                    { { "C", "CH3" },
                      { "C", "H" },
                      { "CH3", "H1" },
                      { "CH3", "H2" },
                      { "CH3", "H3" } },
                    // Double Bonds
                    { { "C", "O" } });
ResidueData MPDData("MPD",
                    // Atoms
                    { "C1",  "C2",  "O2",  "CM",  "C3",  "C4",  "O4",  "C5",
                      "H11", "H12", "H13", "HO2", "HM1", "HM2", "HM3", "H31",
                      "H32", "H4",  "HO4", "H51", "H52", "H53" },
                    // Single Bonds
                    { { "C1", "C2" },  { "C1", "H11" }, { "C1", "H12" },
                      { "C1", "H13" }, { "C2", "O2" },  { "C2", "CM" },
                      { "C2", "C3" },  { "O2", "HO2" }, { "CM", "HM1" },
                      { "CM", "HM2" }, { "CM", "HM3" }, { "C3", "C4" },
                      { "C3", "H31" }, { "C3", "H32" }, { "C4", "O4" },
                      { "C4", "C5" },  { "C4", "H4" },  { "O4", "HO4" },
                      { "C5", "H51" }, { "C5", "H52" }, { "C5", "H53" } },
                    // Double Bonds
                    {});
ResidueData MESData(
  "MES",
  // Atoms
  { "O1",  "C2",  "C3",  "N4",  "C5",  "C6",  "C7",  "C8",  "S",
    "O1S", "O2S", "O3S", "H21", "H22", "H31", "H32", "HN4", "H51",
    "H52", "H61", "H62", "H71", "H72", "H81", "H82" },
  // Single Bonds
  { { "O1", "C2" },  { "O1", "C6" },  { "C2", "C3" },  { "C2", "H21" },
    { "C2", "H22" }, { "C3", "N4" },  { "C3", "H31" }, { "C3", "H32" },
    { "N4", "C5" },  { "N4", "C7" },  { "N4", "HN4" }, { "C5", "C6" },
    { "C5", "H51" }, { "C5", "H52" }, { "C6", "H61" }, { "C6", "H62" },
    { "C7", "C8" },  { "C7", "H71" }, { "C7", "H72" }, { "C8", "S" },
    { "C8", "H81" }, { "C8", "H82" }, { "S", "O3S" } },
  // Double Bonds
  { { "S", "O1S" }, { "S", "O2S" } });
ResidueData NADData(
  "NAD",
  // Atoms
  { "PA",   "O1A",  "O2A", "O5B",  "C5B",  "C4B", "O4B",  "C3B",  "O3B",
    "C2B",  "O2B",  "C1B", "N9A",  "C8A",  "N7A", "C5A",  "C6A",  "N6A",
    "N1A",  "C2A",  "N3A", "C4A",  "O3",   "PN",  "O1N",  "O2N",  "O5D",
    "C5D",  "C4D",  "O4D", "C3D",  "O3D",  "C2D", "O2D",  "C1D",  "N1N",
    "C2N",  "C3N",  "C7N", "O7N",  "N7N",  "C4N", "C5N",  "C6N",  "HOA2",
    "H51A", "H52A", "H4B", "H3B",  "HO3A", "H2B", "HO2A", "H1B",  "H8A",
    "H61A", "H62A", "H2A", "H51N", "H52N", "H4D", "H3D",  "HO3N", "H2D",
    "HO2N", "H1D",  "H2N", "H71N", "H72N", "H4N", "H5N",  "H6N" },
  // Single Bonds
  { { "PA", "O2A" },   { "PA", "O5B" },   { "PA", "O3" },    { "O2A", "HOA2" },
    { "O5B", "C5B" },  { "C5B", "C4B" },  { "C5B", "H51A" }, { "C5B", "H52A" },
    { "C4B", "O4B" },  { "C4B", "C3B" },  { "C4B", "H4B" },  { "O4B", "C1B" },
    { "C3B", "O3B" },  { "C3B", "C2B" },  { "C3B", "H3B" },  { "O3B", "HO3A" },
    { "C2B", "O2B" },  { "C2B", "C1B" },  { "C2B", "H2B" },  { "O2B", "HO2A" },
    { "C1B", "N9A" },  { "C1B", "H1B" },  { "N9A", "C8A" },  { "N9A", "C4A" },
    { "C8A", "H8A" },  { "N7A", "C5A" },  { "C5A", "C6A" },  { "C6A", "N6A" },
    { "N6A", "H61A" }, { "N6A", "H62A" }, { "N1A", "C2A" },  { "C2A", "H2A" },
    { "N3A", "C4A" },  { "O3", "PN" },    { "PN", "O2N" },   { "PN", "O5D" },
    { "O5D", "C5D" },  { "C5D", "C4D" },  { "C5D", "H51N" }, { "C5D", "H52N" },
    { "C4D", "O4D" },  { "C4D", "C3D" },  { "C4D", "H4D" },  { "O4D", "C1D" },
    { "C3D", "O3D" },  { "C3D", "C2D" },  { "C3D", "H3D" },  { "O3D", "HO3N" },
    { "C2D", "O2D" },  { "C2D", "C1D" },  { "C2D", "H2D" },  { "O2D", "HO2N" },
    { "C1D", "N1N" },  { "C1D", "H1D" },  { "N1N", "C2N" },  { "C2N", "H2N" },
    { "C3N", "C7N" },  { "C3N", "C4N" },  { "C7N", "N7N" },  { "N7N", "H71N" },
    { "N7N", "H72N" }, { "C4N", "H4N" },  { "C5N", "C6N" },  { "C5N", "H5N" },
    { "C6N", "H6N" } },
  // Double Bonds
  { { "PA", "O1A" },
    { "C8A", "N7A" },
    { "C5A", "C4A" },
    { "C6A", "N1A" },
    { "C2A", "N3A" },
    { "PN", "O1N" },
    { "N1N", "C6N" },
    { "C2N", "C3N" },
    { "C7N", "O7N" },
    { "C4N", "C5N" } });
ResidueData NAPData(
  "NAP",
  // Atoms
  { "PA",  "O1A",  "O2A",  "O5B",  "C5B",  "C4B",  "O4B",  "C3B",  "O3B",
    "C2B", "O2B",  "C1B",  "N9A",  "C8A",  "N7A",  "C5A",  "C6A",  "N6A",
    "N1A", "C2A",  "N3A",  "C4A",  "O3",   "PN",   "O1N",  "O2N",  "O5D",
    "C5D", "C4D",  "O4D",  "C3D",  "O3D",  "C2D",  "O2D",  "C1D",  "N1N",
    "C2N", "C3N",  "C7N",  "O7N",  "N7N",  "C4N",  "C5N",  "C6N",  "P2B",
    "O1X", "O2X",  "O3X",  "HOA2", "H51A", "H52A", "H4B",  "H3B",  "HO3A",
    "H2B", "H1B",  "H8A",  "H61A", "H62A", "H2A",  "H51N", "H52N", "H4D",
    "H3D", "HO3N", "H2D",  "HO2N", "H1D",  "H2N",  "H71N", "H72N", "H4N",
    "H5N", "H6N",  "HOP2", "HOP3" },
  // Single Bonds
  { { "PA", "O2A" },   { "PA", "O5B" },   { "PA", "O3" },    { "O2A", "HOA2" },
    { "O5B", "C5B" },  { "C5B", "C4B" },  { "C5B", "H51A" }, { "C5B", "H52A" },
    { "C4B", "O4B" },  { "C4B", "C3B" },  { "C4B", "H4B" },  { "O4B", "C1B" },
    { "C3B", "O3B" },  { "C3B", "C2B" },  { "C3B", "H3B" },  { "O3B", "HO3A" },
    { "C2B", "O2B" },  { "C2B", "C1B" },  { "C2B", "H2B" },  { "O2B", "P2B" },
    { "C1B", "N9A" },  { "C1B", "H1B" },  { "N9A", "C8A" },  { "N9A", "C4A" },
    { "C8A", "H8A" },  { "N7A", "C5A" },  { "C5A", "C6A" },  { "C6A", "N6A" },
    { "N6A", "H61A" }, { "N6A", "H62A" }, { "N1A", "C2A" },  { "C2A", "H2A" },
    { "N3A", "C4A" },  { "O3", "PN" },    { "PN", "O2N" },   { "PN", "O5D" },
    { "O5D", "C5D" },  { "C5D", "C4D" },  { "C5D", "H51N" }, { "C5D", "H52N" },
    { "C4D", "O4D" },  { "C4D", "C3D" },  { "C4D", "H4D" },  { "O4D", "C1D" },
    { "C3D", "O3D" },  { "C3D", "C2D" },  { "C3D", "H3D" },  { "O3D", "HO3N" },
    { "C2D", "O2D" },  { "C2D", "C1D" },  { "C2D", "H2D" },  { "O2D", "HO2N" },
    { "C1D", "N1N" },  { "C1D", "H1D" },  { "N1N", "C2N" },  { "C2N", "H2N" },
    { "C3N", "C7N" },  { "C3N", "C4N" },  { "C7N", "N7N" },  { "N7N", "H71N" },
    { "N7N", "H72N" }, { "C4N", "H4N" },  { "C5N", "C6N" },  { "C5N", "H5N" },
    { "C6N", "H6N" },  { "P2B", "O2X" },  { "P2B", "O3X" },  { "O2X", "HOP2" },
    { "O3X", "HOP3" } },
  // Double Bonds
  { { "PA", "O1A" },
    { "C8A", "N7A" },
    { "C5A", "C4A" },
    { "C6A", "N1A" },
    { "C2A", "N3A" },
    { "PN", "O1N" },
    { "N1N", "C6N" },
    { "C2N", "C3N" },
    { "C7N", "O7N" },
    { "C4N", "C5N" },
    { "P2B", "O1X" } });
ResidueData TRSData("TRS",
                    // Atoms
                    { "C",   "C1",  "C2",  "C3",  "N",   "O1",  "O2",
                      "O3",  "H11", "H12", "H21", "H22", "H31", "H32",
                      "HN1", "HN2", "HN3", "HO1", "HO2", "HO3" },
                    // Single Bonds
                    { { "C", "C1" },
                      { "C", "C2" },
                      { "C", "C3" },
                      { "C", "N" },
                      { "C1", "O1" },
                      { "C1", "H11" },
                      { "C1", "H12" },
                      { "C2", "O2" },
                      { "C2", "H21" },
                      { "C2", "H22" },
                      { "C3", "O3" },
                      { "C3", "H31" },
                      { "C3", "H32" },
                      { "N", "HN1" },
                      { "N", "HN2" },
                      { "N", "HN3" },
                      { "O1", "HO1" },
                      { "O2", "HO2" },
                      { "O3", "HO3" } },
                    // Double Bonds
                    {});
ResidueData ATPData(
  "ATP",
  // Atoms
  { "PG",  "O1G",  "O2G",  "O3G",  "PB",   "O1B",  "O2B",  "O3B", "PA",  "O1A",
    "O2A", "O3A",  "O5'",  "C5'",  "C4'",  "O4'",  "C3'",  "O3'", "C2'", "O2'",
    "C1'", "N9",   "C8",   "N7",   "C5",   "C6",   "N6",   "N1",  "C2",  "N3",
    "C4",  "HOG2", "HOG3", "HOB2", "HOA2", "H5'1", "H5'2", "H4'", "H3'", "HO3'",
    "H2'", "HO2'", "H1'",  "H8",   "HN61", "HN62", "H2" },
  // Single Bonds
  { { "PG", "O2G" },   { "PG", "O3G" },  { "PG", "O3B" },  { "O2G", "HOG2" },
    { "O3G", "HOG3" }, { "PB", "O2B" },  { "PB", "O3B" },  { "PB", "O3A" },
    { "O2B", "HOB2" }, { "PA", "O2A" },  { "PA", "O3A" },  { "PA", "O5'" },
    { "O2A", "HOA2" }, { "O5'", "C5'" }, { "C5'", "C4'" }, { "C5'", "H5'1" },
    { "C5'", "H5'2" }, { "C4'", "O4'" }, { "C4'", "C3'" }, { "C4'", "H4'" },
    { "O4'", "C1'" },  { "C3'", "O3'" }, { "C3'", "C2'" }, { "C3'", "H3'" },
    { "O3'", "HO3'" }, { "C2'", "O2'" }, { "C2'", "C1'" }, { "C2'", "H2'" },
    { "O2'", "HO2'" }, { "C1'", "N9" },  { "C1'", "H1'" }, { "N9", "C8" },
    { "N9", "C4" },    { "C8", "H8" },   { "N7", "C5" },   { "C5", "C6" },
    { "C6", "N6" },    { "N6", "HN61" }, { "N6", "HN62" }, { "N1", "C2" },
    { "C2", "H2" },    { "N3", "C4" } },
  // Double Bonds
  { { "PG", "O1G" },
    { "PB", "O1B" },
    { "PA", "O1A" },
    { "C8", "N7" },
    { "C5", "C4" },
    { "C6", "N1" },
    { "C2", "N3" } });
ResidueData NH2Data("NH2",
                    // Atoms
                    { "N", "HN1", "HN2" },
                    // Single Bonds
                    { { "N", "HN1" }, { "N", "HN2" } },
                    // Double Bonds
                    {});
ResidueData PG4Data(
  "PG4",
  // Atoms
  { "O1",  "C1",  "C2",  "O2",  "C3",  "C4",  "O3",  "C5",  "C6",  "O4",  "C7",
    "C8",  "O5",  "HO1", "H11", "H12", "H21", "H22", "H31", "H32", "H41", "H42",
    "H51", "H52", "H61", "H62", "H71", "H72", "H81", "H82", "HO5" },
  // Single Bonds
  { { "O1", "C1" },  { "O1", "HO1" }, { "C1", "C2" },  { "C1", "H11" },
    { "C1", "H12" }, { "C2", "O2" },  { "C2", "H21" }, { "C2", "H22" },
    { "O2", "C3" },  { "C3", "C4" },  { "C3", "H31" }, { "C3", "H32" },
    { "C4", "O3" },  { "C4", "H41" }, { "C4", "H42" }, { "O3", "C5" },
    { "C5", "C6" },  { "C5", "H51" }, { "C5", "H52" }, { "C6", "O4" },
    { "C6", "H61" }, { "C6", "H62" }, { "O4", "C7" },  { "C7", "C8" },
    { "C7", "H71" }, { "C7", "H72" }, { "C8", "O5" },  { "C8", "H81" },
    { "C8", "H82" }, { "O5", "HO5" } },
  // Double Bonds
  {});
ResidueData FMTData("FMT",
                    // Atoms
                    { "C", "O1", "O2", "H", "HO2" },
                    // Single Bonds
                    { { "C", "O2" }, { "C", "H" }, { "O2", "HO2" } },
                    // Double Bonds
                    { { "C", "O1" } });
ResidueData GDPData(
  "GDP",
  // Atoms
  { "PB",  "O1B",  "O2B",  "O3B",  "O3A", "PA",   "O1A", "O2A", "O5'",
    "C5'", "C4'",  "O4'",  "C3'",  "O3'", "C2'",  "O2'", "C1'", "N9",
    "C8",  "N7",   "C5",   "C6",   "O6",  "N1",   "C2",  "N2",  "N3",
    "C4",  "HOB2", "HOB3", "HOA2", "H5'", "H5''", "H4'", "H3'", "HO3'",
    "H2'", "HO2'", "H1'",  "H8",   "HN1", "HN21", "HN22" },
  // Single Bonds
  { { "PB", "O2B" },   { "PB", "O3B" },  { "PB", "O3A" },  { "O2B", "HOB2" },
    { "O3B", "HOB3" }, { "O3A", "PA" },  { "PA", "O2A" },  { "PA", "O5'" },
    { "O2A", "HOA2" }, { "O5'", "C5'" }, { "C5'", "C4'" }, { "C5'", "H5'" },
    { "C5'", "H5''" }, { "C4'", "O4'" }, { "C4'", "C3'" }, { "C4'", "H4'" },
    { "O4'", "C1'" },  { "C3'", "O3'" }, { "C3'", "C2'" }, { "C3'", "H3'" },
    { "O3'", "HO3'" }, { "C2'", "O2'" }, { "C2'", "C1'" }, { "C2'", "H2'" },
    { "O2'", "HO2'" }, { "C1'", "N9" },  { "C1'", "H1'" }, { "N9", "C8" },
    { "N9", "C4" },    { "C8", "H8" },   { "N7", "C5" },   { "C5", "C6" },
    { "C6", "N1" },    { "N1", "C2" },   { "N1", "HN1" },  { "C2", "N2" },
    { "N2", "HN21" },  { "N2", "HN22" }, { "N3", "C4" } },
  // Double Bonds
  { { "PB", "O1B" },
    { "PA", "O1A" },
    { "C8", "N7" },
    { "C5", "C4" },
    { "C6", "O6" },
    { "C2", "N3" } });
ResidueData FUCData("FUC",
                    // Atoms
                    { "C1",  "C2",  "C3",  "C4",  "C5",  "C6",  "O1", "O2",
                      "O3",  "O4",  "O5",  "H1",  "H2",  "H3",  "H4", "H5",
                      "H61", "H62", "H63", "HO1", "HO2", "HO3", "HO4" },
                    // Single Bonds
                    { { "C1", "C2" },  { "C1", "O1" },  { "C1", "O5" },
                      { "C1", "H1" },  { "C2", "C3" },  { "C2", "O2" },
                      { "C2", "H2" },  { "C3", "C4" },  { "C3", "O3" },
                      { "C3", "H3" },  { "C4", "C5" },  { "C4", "O4" },
                      { "C4", "H4" },  { "C5", "C6" },  { "C5", "O5" },
                      { "C5", "H5" },  { "C6", "H61" }, { "C6", "H62" },
                      { "C6", "H63" }, { "O1", "HO1" }, { "O2", "HO2" },
                      { "O3", "HO3" }, { "O4", "HO4" } },
                    // Double Bonds
                    {});
ResidueData SEPData("SEP",
                    // Atoms
                    { "N", "CA", "CB", "OG", "C", "O", "OXT", "P", "O1P", "O2P",
                      "O3P", "H", "H2", "HA", "HB2", "HB3", "HXT", "HOP2",
                      "HOP3" },
                    // Single Bonds
                    { { "N", "CA" },
                      { "N", "H" },
                      { "N", "H2" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CA", "HA" },
                      { "CB", "OG" },
                      { "CB", "HB2" },
                      { "CB", "HB3" },
                      { "OG", "P" },
                      { "C", "OXT" },
                      { "OXT", "HXT" },
                      { "P", "O2P" },
                      { "P", "O3P" },
                      { "O2P", "HOP2" },
                      { "O3P", "HOP3" } },
                    // Double Bonds
                    { { "C", "O" }, { "P", "O1P" } });
ResidueData GALData("GAL",
                    // Atoms
                    { "C1", "C2",  "C3",  "C4",  "C5",  "C6",  "O1",  "O2",
                      "O3", "O4",  "O5",  "O6",  "H1",  "H2",  "H3",  "H4",
                      "H5", "H61", "H62", "HO1", "HO2", "HO3", "HO4", "HO6" },
                    // Single Bonds
                    { { "C1", "C2" },  { "C1", "O1" },  { "C1", "O5" },
                      { "C1", "H1" },  { "C2", "C3" },  { "C2", "O2" },
                      { "C2", "H2" },  { "C3", "C4" },  { "C3", "O3" },
                      { "C3", "H3" },  { "C4", "C5" },  { "C4", "O4" },
                      { "C4", "H4" },  { "C5", "C6" },  { "C5", "O5" },
                      { "C5", "H5" },  { "C6", "O6" },  { "C6", "H61" },
                      { "C6", "H62" }, { "O1", "HO1" }, { "O2", "HO2" },
                      { "O3", "HO3" }, { "O4", "HO4" }, { "O6", "HO6" } },
                    // Double Bonds
                    {});
ResidueData PGEData("PGE",
                    // Atoms
                    { "C1",  "O1", "C2",  "O2",  "C3",  "C4",  "O4",  "C6",
                      "C5",  "O3", "H1",  "H12", "HO1", "H2",  "H22", "H3",
                      "H32", "H4", "H42", "HO4", "H6",  "H62", "H5",  "H52" },
                    // Single Bonds
                    { { "C1", "O1" },  { "C1", "C2" },  { "C1", "H1" },
                      { "C1", "H12" }, { "O1", "HO1" }, { "C2", "O2" },
                      { "C2", "H2" },  { "C2", "H22" }, { "O2", "C3" },
                      { "C3", "C4" },  { "C3", "H3" },  { "C3", "H32" },
                      { "C4", "O3" },  { "C4", "H4" },  { "C4", "H42" },
                      { "O4", "C6" },  { "O4", "HO4" }, { "C6", "C5" },
                      { "C6", "H6" },  { "C6", "H62" }, { "C5", "O3" },
                      { "C5", "H5" },  { "C5", "H52" } },
                    // Double Bonds
                    {});

ResidueData ASHData("ASH",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "CG", "OD2", "OD1" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "CG" },
                      { "CG", "OD2" },
                      { "N", "H" },
                      { "N", "HN" },
                      { "OD2", "HD2" } },
                    // Double Bonds
                    { { "C", "O" }, { "CG", "OD1" } });

ResidueData CYXData("CYX",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "SG" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "SG" },
                      { "N", "H" } },
                    // Double Bonds
                    { { "C", "O" } });

ResidueData HIPData("HIP",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "CG", "ND1", "CD2", "NE2",
                      "CE1" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "CG" },
                      { "CG", "ND1" },
                      { "CD2", "NE2" },
                      { "NE2", "CE1" },
                      { "CE1", "ND1" },
                      { "N", "H" },
                      { "ND1", "HD1" },
                      { "NE2", "HE2" } },
                    // Double Bonds
                    { { "C", "O" }, { "CG", "CD2" } });

ResidueData HIDData("HID",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "CG", "ND1", "CD2", "NE2",
                      "CE1" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "CG" },
                      { "CG", "ND1" },
                      { "CD2", "NE2" },
                      { "CE1", "ND1" },
                      { "N", "H" },
                      { "ND1", "HD1" } },
                    // Double Bonds
                    { { "C", "O" }, { "CG", "CD2" }, { "NE2", "CE1" } });

ResidueData HIEData("HIE",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "CG", "ND1", "CD2", "NE2",
                      "CE1" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "CG" },
                      { "CG", "ND1" },
                      { "CD2", "NE2" },
                      { "NE2", "CE1" },
                      { "CE1", "ND1" },
                      { "N", "H" },
                      { "NE2", "HE2" } },
                    // Double Bonds
                    { { "C", "O" }, { "CG", "CD2" } });

std::map<std::string, ResidueData> residueDict = {
  { "ALA", ALAData }, { "CYS", CYSData }, { "ASP", ASPData },
  { "GLU", GLUData }, { "PHE", PHEData }, { "GLY", GLYData },
  { "HIS", HISData }, { "ILE", ILEData }, { "LYS", LYSData },
  { "LEU", LEUData }, { "MET", METData }, { "ASN", ASNData },
  { "PRO", PROData }, { "GLN", GLNData }, { "ARG", ARGData },
  { "SER", SERData }, { "THR", THRData }, { "VAL", VALData },
  { "TRP", TRPData }, { "TYR", TYRData }, { "DA", DAData },
  { "DC", DCData },   { "DG", DGData },   { "DT", DTData },
  { "DI", DIData },   { "A", AData },     { "C", CData },
  { "G", GData },     { "U", UData },     { "I", IData },
  { "HEM", HEMData }, { "HOH", HOHData }, { "SO4", SO4Data },
  { "GOL", GOLData }, { "MSE", MSEData }, { "EDO", EDOData },
  { "NAG", NAGData }, { "PO4", PO4Data }, { "ACT", ACTData },
  { "PEG", PEGData }, { "MAN", MANData }, { "BMA", BMAData },
  { "FAD", FADData }, { "ADP", ADPData }, { "DMS", DMSData },
  { "ACE", ACEData }, { "MPD", MPDData }, { "MES", MESData },
  { "NAD", NADData }, { "NAP", NAPData }, { "TRS", TRSData },
  { "ATP", ATPData }, { "NH2", NH2Data }, { "PG4", PG4Data },
  { "FMT", FMTData }, { "GDP", GDPData }, { "FUC", FUCData },
  { "SEP", SEPData }, { "GAL", GALData }, { "PGE", PGEData },
  { "ASH", ASHData }, { "CYX", CYXData }, { "HIP", HIPData },
  { "HID", HIDData }, { "HIE", HIEData },
};

} // namespace Core
} // namespace Avogadro

#endif
