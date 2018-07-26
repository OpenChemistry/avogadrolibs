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
                    { "CA", "N", "CB", "C", "O" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "N", "H" },
                      { "N", "HN" },
                      { "HA", "CA" },
                      { "HB1", "CB" },
                      { "HB2", "CB" },
                      { "HB3", "CB" } },
                    // Double Bonds
                    { { "C", "O" } });

ResidueData ARGData(
  "ARG",
  // Atoms
  { "CA", "N", "CB", "C", "O", "CG", "CD", "NE", "CZ", "NH2", "NH1" },
  // Single Bonds
  { { "CA", "N" },    { "CA", "CB" },    { "CA", "C" },     { "CB", "CG" },
    { "CG", "CD" },   { "CD", "NE" },    { "NE", "CZ" },    { "CZ", "NH1" },
    { "N", "H" },     { "HN", "N" },     { "NH1", "HH11" }, { "NH1", "HH12" },
    { "NE", "HE" },   { "NH2", "HH21" }, { "NH2", "HH22" }, { "NH1", "HH1" },
    { "NH2", "HH2" }, { "HB1", "CB" },   { "HB2", "CB" },   { "HD1", "CD" },
    { "HD2", "CD" },  { "HG1", "CG" },   { "HG2", "CG" } },
  // Double Bonds
  { { "C", "O" }, { "CZ", "NH2" } });

ResidueData ARZData("ARZ",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "CG", "CD", "NE", "CZ", "NH2",
                      "NH1" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "CG" },
                      { "CG", "CD" },
                      { "CD", "NE" },
                      { "NE", "CZ" },
                      { "CZ", "NH2" },
                      { "N", "H" },
                      { "N", "HN" },
                      { "NH1", "HH1" },
                      { "NE", "HE" },
                      { "NH2", "HH21" },
                      { "NH2", "HH22" } },
                    // Double Bonds
                    { { "C", "O" }, { "CZ", "NH1" } });

ResidueData ASNData("ASN",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "CG", "ND2", "OD1" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "CG" },
                      { "CG", "ND2" },
                      { "N", "H" },
                      { "N", "HN" },
                      { "HA", "CA" },
                      { "HB1", "CB" },
                      { "HB2", "CB" },
                      { "ND2", "HD21" },
                      { "ND2", "HD22" },
                      { "ND2", "HD2" } },
                    // Double Bonds
                    { { "C", "O" }, { "CG", "OD1" } });

ResidueData ASPData("ASP",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "CG", "OD2", "OD1" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "CG" },
                      { "CG", "OD1" },
                      { "N", "H" },
                      { "N", "HN" },
                      { "HA", "CA" },
                      { "HB1", "CB" },
                      { "HB2", "CB" } },
                    // Double Bonds
                    { { "C", "O" }, { "CG", "OD2" } });

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

ResidueData CYSData("CYS",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "SG" },
                    // Single Bonds
                    { { "SG", "CB" },
                      { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "SG" },
                      { "N", "H" },
                      { "N", "HN" },
                      { "CA", "HA" },
                      { "HB1", "CB" },
                      { "HB2", "CB" },
                      { "SG", "HG" } },
                    // Double Bonds
                    { { "C", "O" } });

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

ResidueData GLNData("GLN",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "CG", "CD", "NE2", "OE1" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "CG" },
                      { "CG", "CD" },
                      { "CD", "NE2" },
                      { "N", "H" },
                      { "N", "HN" },
                      { "CA", "HA" },
                      { "HB1", "CB" },
                      { "HB2", "CB" },
                      { "HG1", "CG" },
                      { "HG2", "CG" },
                      { "NE2", "HE21" },
                      { "NE2", "HE22" },
                      { "NE2", "HE2" } },
                    // Double Bonds
                    { { "C", "O" }, { "CD", "OE1" } });

ResidueData GLUData("GLU",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "CG", "CD", "OE2", "OE1" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "CG" },
                      { "CG", "CD" },
                      { "CD", "OE2" },
                      { "N", "H" },
                      { "N", "H1" },
                      { "N", "H2" },
                      { "N", "H3" },
                      { "HA", "CA" },
                      { "HB1", "CB" },
                      { "HB2", "CB" },
                      { "HG1", "CG" },
                      { "HG2", "CG" } },
                    // Double Bonds
                    { { "C", "O" }, { "CD", "OE1" } });

ResidueData GLYData("GLY",
                    // Atoms
                    { "CA", "N", "C", "O" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "C" },
                      { "N", "H" },
                      { "N", "HN" },
                      { "HA1", "CA" },
                      { "HA2", "CA" } },
                    // Double Bonds
                    { { "C", "O" } });

ResidueData GLZData("GLZ",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "CG", "CD", "OE2", "OE1" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "CG" },
                      { "CG", "CD" },
                      { "CD", "OE2" },
                      { "N", "H" },
                      { "OE2", "HE2" } },
                    // Double Bonds
                    { { "C", "O" }, { "CD", "OE1" } });

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

ResidueData HISData("HIS",
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
                      { "N", "HN" },
                      { "HA", "CA" },
                      { "HB1", "CB" },
                      { "HB2", "CB" },
                      { "HD1", "ND1" },
                      { "HD2", "CD2" },
                      { "HE1", "CE1" },
                      { "ND1", "HD1" },
                      { "NE2", "HE2" } },
                    // Double Bonds
                    { { "C", "O" }, { "CG", "CD2" }, { "NE2", "CE1" } });

ResidueData ILEData("ILE",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "CG2", "CG1", "CD1" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "CG2" },
                      { "CB", "CG1" },
                      { "CG1", "CD1" },
                      { "N", "H" },
                      { "N", "HN" },
                      { "CA", "HA" },
                      { "HB", "CB" },
                      { "HG11", "CG1" },
                      { "HG12", "CG1" },
                      { "HG21", "CG2" },
                      { "HG22", "CG2" },
                      { "HG23", "CG2" },
                      { "HD11", "CD1" },
                      { "HD12", "CD1" },
                      { "HD13", "CD1" } },
                    // Double Bonds
                    { { "C", "O" } });

ResidueData LEUData("LEU",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "CG", "CD1", "CD2" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "CG" },
                      { "CG", "CD1" },
                      { "CG", "CD2" },
                      { "N", "H" },
                      { "N", "HN" },
                      { "HA", "CA" },
                      { "HB1", "CB" },
                      { "HB2", "CB" },
                      { "HD11", "CD1" },
                      { "HD12", "CD1" },
                      { "HD13", "CD1" },
                      { "HD21", "CD2" },
                      { "HD22", "CD2" },
                      { "HD23", "CD2" },
                      { "HG", "CG" } },
                    // Double Bonds
                    { { "C", "O" } });

ResidueData LYSData("LYS",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "CG", "CD", "CE", "NZ" },
                    // Single Bonds
                    { { "CA", "N" },   { "CA", "CB" },  { "CA", "C" },
                      { "CB", "CG" },  { "CG", "CD" },  { "CD", "CE" },
                      { "CE", "NZ" },  { "N", "H" },    { "N", "HN" },
                      { "HA", "CA" },  { "HB1", "CB" }, { "HB2", "CB" },
                      { "HD1", "CD" }, { "HD2", "CD" }, { "HG1", "CG" },
                      { "HG2", "CG" }, { "HE1", "CE" }, { "HE2", "CE" },
                      { "NZ", "HZ3" }, { "NZ", "HZ3" }, { "NZ", "HZ2" },
                      { "NZ", "HZ2" }, { "NZ", "HZ1" }, { "NZ", "HZ1" } },
                    // Double Bonds
                    { { "C", "O" } });

ResidueData LYZData("LYZ",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "CG", "CD", "CE", "NZ" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "CG" },
                      { "CG", "CD" },
                      { "CD", "CE" },
                      { "CE", "NZ" },
                      { "N", "H" },
                      { "NZ", "HZ2" },
                      { "NZ", "HZ1" } },
                    // Double Bonds
                    { { "C", "O" } });

ResidueData METData("MET",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "CG", "SD", "CE" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "CG" },
                      { "CG", "SD" },
                      { "SD", "CE" },
                      { "N", "H" },
                      { "N", "HN" },
                      { "HA", "CA" },
                      { "HB1", "CB" },
                      { "HB2", "CB" },
                      { "HG1", "CG" },
                      { "HG2", "CG" },
                      { "HE1", "CE" },
                      { "HE2", "CE" },
                      { "HE3", "CE" } },
                    // Double Bonds
                    { { "C", "O" } });

ResidueData PHEData(
  "PHE",
  // Atoms
  { "CA", "N", "CB", "C", "O", "CG", "CD1", "CD2", "CE2", "CZ", "CE1" },
  // Single Bonds
  { { "CA", "N" },
    { "CA", "CB" },
    { "CA", "C" },
    { "CB", "CG" },
    { "CG", "CD1" },
    { "CD2", "CE2" },
    { "CZ", "CE1" },
    { "N", "H" },
    { "N", "HN" },
    { "HA", "CA" },
    { "HB1", "CB" },
    { "HB2", "CB" },
    { "HD1", "CD1" },
    { "HD2", "CD2" },
    { "HE1", "CE1" },
    { "HE2", "CE2" },
    { "HZ", "CZ" } },
  // Double Bonds
  { { "C", "O" }, { "CG", "CD2" }, { "CE2", "CZ" }, { "CE1", "CD1" } });

ResidueData PROData("PRO",
                    // Atoms
                    { "CA", "C", "CB", "N", "CD", "CG", "O" },
                    // Single Bonds
                    { { "CA", "C" },
                      { "CA", "CB" },
                      { "CA", "N" },
                      { "N", "CD" },
                      { "CD", "CG" },
                      { "CG", "CB" },
                      { "HB1", "CB" },
                      { "HB2", "CB" },
                      { "HG1", "CG" },
                      { "HG2", "CG" },
                      { "HD1", "CD" },
                      { "HD2", "CD" },
                      { "HA", "CA" },
                      { "HN", "N" } },
                    // Double Bonds
                    { { "C", "O" } });

ResidueData PSEData("PSE",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "OG", "PD", "OE2", "OE3",
                      "OE1" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "OG" },
                      { "OG", "PD" },
                      { "PD", "OE2" },
                      { "PD", "OE3" },
                      { "PD", "OE1" },
                      { "N", "H" } },
                    // Double Bonds
                    { { "C", "O" } });

ResidueData PSMData("PSM",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "OG", "PD", "OE2", "OE3",
                      "OE1" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "OG" },
                      { "OG", "PD" },
                      { "PD", "OE2" },
                      { "PD", "OE3" },
                      { "PD", "OE1" },
                      { "N", "H" },
                      { "OE3", "HE3" } },
                    // Double Bonds
                    { { "C", "O" } });

ResidueData PTMData(
  "PTM",
  // Atoms
  { "CA", "N", "CB", "C", "O", "CG", "CD1", "CD2", "CE2", "CZ", "OH", "CE1",
    "PQ", "OI3", "OI2", "OI1" },
  // Single Bonds
  { { "CA", "N" },
    { "CA", "CB" },
    { "CA", "C" },
    { "CB", "CG" },
    { "CG", "CD2" },
    { "CE2", "CZ" },
    { "CZ", "OH" },
    { "CE1", "CD1" },
    { "OH", "PQ" },
    { "PQ", "OI3" },
    { "PQ", "OI2" },
    { "PQ", "OI1" },
    { "N", "H" },
    { "OI2", "HI2" } },
  // Double Bonds
  { { "C", "O" }, { "CG", "CD1" }, { "CD2", "CE2" }, { "CZ", "CE1" } });

ResidueData PTYData(
  "PTY",
  // Atoms
  { "CA", "N", "CB", "C", "O", "CG", "CD1", "CD2", "CE2", "CZ", "OH", "CE1",
    "PQ", "OI3", "OI2", "OI1" },
  // Single Bonds
  { { "CA", "N" },
    { "CA", "CB" },
    { "CA", "C" },
    { "CB", "CG" },
    { "CG", "CD2" },
    { "CE2", "CZ" },
    { "CZ", "OH" },
    { "CE1", "CD1" },
    { "OH", "PQ" },
    { "PQ", "OI3" },
    { "PQ", "OI2" },
    { "PQ", "OI1" },
    { "N", "H" } },
  // Double Bonds
  { { "C", "O" }, { "CG", "CD1" }, { "CD2", "CE2" }, { "CZ", "CE1" } });

ResidueData SERData("SER",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "OG" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "OG" },
                      { "N", "H" },
                      { "N", "HN" },
                      { "HA", "CA" },
                      { "HB1", "CB" },
                      { "HB2", "CB" },
                      { "OG", "HG" } },
                    // Double Bonds
                    { { "C", "O" } });

ResidueData THRData("THR",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "CG2", "OG1" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "CG2" },
                      { "CB", "OG1" },
                      { "N", "H" },
                      { "HN", "N" },
                      { "N", "H1" },
                      { "N", "H2" },
                      { "N", "H3" },
                      { "OG1", "HG1" },
                      { "OG1", "HG1" },
                      { "HB", "CB" },
                      { "HA", "CA" },
                      { "HG21", "CG2" },
                      { "HG22", "CG2" },
                      { "HG23", "CG2" } },
                    // Double Bonds
                    { { "C", "O" } });

ResidueData TRPData("TRP",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "CG", "CD1", "CD2", "CE3",
                      "CE2", "CZ2", "NE1", "CH2", "CZ3" },
                    // Single Bonds
                    { { "CA", "N" },    { "CA", "CB" },   { "CA", "C" },
                      { "CB", "CG" },   { "CG", "CD2" },  { "CD2", "CE2" },
                      { "CE2", "NE1" }, { "NE1", "CD1" }, { "CZ2", "CH2" },
                      { "CZ3", "CE3" }, { "N", "H" },     { "N", "HN" },
                      { "HA", "CA" },   { "HB1", "CB" },  { "HB2", "CB" },
                      { "HD1", "CD1" }, { "HE1", "CE1" }, { "HZ2", "CZ2" },
                      { "HZ3", "CZ3" }, { "HE3", "CE3" }, { "HH2", "CH2" },
                      { "NE1", "HE1" }, { "NE1", "HE1" } },
                    // Double Bonds
                    { { "C", "O" },
                      { "CG", "CD1" },
                      { "CD2", "CE3" },
                      { "CE2", "CZ2" },
                      { "CH2", "CZ3" } });

ResidueData TYRData(
  "TYR",
  // Atoms
  { "CA", "N", "CB", "C", "O", "CG", "CD1", "CD2", "CE2", "CZ", "OH", "CE1" },
  // Single Bonds
  { { "CA", "N" },
    { "CA", "CB" },
    { "CA", "C" },
    { "CB", "CG" },
    { "CG", "CD2" },
    { "CE2", "CZ" },
    { "CZ", "OH" },
    { "CE1", "CD1" },
    { "N", "H" },
    { "OH", "HH" },
    { "N", "HN" },
    { "HA", "CA" },
    { "HB1", "CB" },
    { "HB2", "CB" },
    { "HD1", "CD1" },
    { "HD2", "CD2" },
    { "HE1", "CE1" },
    { "HE2", "CE2" },
    { "HZ", "CZ" } },
  // Double Bonds
  { { "C", "O" }, { "CG", "CD1" }, { "CD2", "CE2" }, { "CZ", "CE1" } });

ResidueData VALData("VAL",
                    // Atoms
                    { "CA", "N", "CB", "C", "O", "CG2", "CG1" },
                    // Single Bonds
                    { { "CA", "N" },
                      { "CA", "CB" },
                      { "CA", "C" },
                      { "CB", "CG2" },
                      { "CB", "CG1" },
                      { "N", "H" },
                      { "N", "HN" },
                      { "HA", "CA" },
                      { "HB", "CB" },
                      { "HG11", "CG1" },
                      { "HG12", "CG1" },
                      { "HG13", "CG1" },
                      { "HG21", "CG2" },
                      { "HG22", "CG2" },
                      { "HG23", "CG2" } },
                    // Double Bonds
                    { { "C", "O" } });

ResidueData TIPData("TIP",
                    // Atoms
                    { "OH2" },
                    // Single Bonds
                    { { "OH2", "H1" }, { "OH2", "H2" } },
                    // Double Bonds
                    {});

ResidueData HOHData("HOH",
                    // Atoms
                    { "O", "H1", "H2" },
                    // Single Bonds
                    { { "O", "H1" }, { "O", "H2" } },
                    // Double Bonds
                    {});

ResidueData WATData("WAT",
                    // Atoms
                    { "O", "H1", "H2" },
                    // Single Bonds
                    { { "O", "H1" }, { "O", "H2" } },
                    // Double Bonds
                    {});

ResidueData INHData(
  "INH",
  // Atoms
  { "P",  "O1P", "O2P", "O3P", "O5", "C5", "C4", "O4", "C3", "C1",
    "O3", "C2",  "O2",  "N9",  "C8", "N7", "C6", "O6", "N1", "N3" },
  // Single Bonds
  { { "P", "O2P" }, { "P", "O3P" }, { "P", "O5" },  { "O5", "C5" },
    { "C5", "C4" }, { "C4", "O4" }, { "C4", "C3" }, { "O4", "C1" },
    { "C3", "O3" }, { "C3", "C2" }, { "O3", "H1" }, { "C2", "O2" },
    { "C2", "C1" }, { "O2", "H2" }, { "C1", "N9" }, { "N9", "C8" },
    { "N9", "C4" }, { "N7", "C5" }, { "C5", "C6" }, { "C6", "N1" },
    { "N1", "C2" }, { "N1", "H3" }, { "N3", "C4" } },
  // Double Bonds
  { { "P", "O1P" }, { "C8", "N7" }, { "C6", "O6" }, { "C2", "N3" } });

ResidueData UMPData("UMP",
                    // Atoms
                    { "N1", "C2", "C6", "C1", "N3", "O2", "C4", "C5", "O4",
                      "C3", "O3", "O5", "P", "O1P", "O2P", "O3P" },
                    // Single Bonds
                    { { "N1", "C2" },  { "N1", "C6" },  { "N1", "C1" },
                      { "C2", "N3" },  { "C2", "O2" },  { "C2", "H5" },
                      { "N3", "C4" },  { "N3", "H1" },  { "C4", "C5" },
                      { "C4", "O4" },  { "C4", "H6" },  { "C5", "C6" },
                      { "C5", "H7" },  { "C5", "H8" },  { "C6", "H9" },
                      { "C6", "H10" }, { "O2", "H2" },  { "O4", "H3" },
                      { "C1", "C2" },  { "C1", "O4" },  { "C1", "H11" },
                      { "C2", "C3" },  { "C2", "H12" }, { "C2", "H13" },
                      { "C3", "C4" },  { "C3", "O3" },  { "C3", "H14" },
                      { "C4", "H15" }, { "O3", "H4" },  { "C5", "O5" },
                      { "C5", "H16" }, { "C5", "H17" }, { "O5", "P" } },
                    // Double Bonds
                    { { "P", "O1P" }, { "P", "O2P" }, { "P", "O3P" } });

ResidueData HEDData("HED",
                    // Atoms
                    { "C1", "O1", "C2", "S3", "S4", "C5", "C6", "O6" },
                    // Single Bonds
                    { { "C1", "C2" },
                      { "C2", "S3" },
                      { "S3", "S4" },
                      { "S4", "C5" },
                      { "C5", "C6" } },
                    // Double Bonds
                    { { "C1", "O1" }, { "C6", "O6" } });

std::map<std::string, ResidueData> residueDict = {
  { "ALA", ALAData }, { "ARG", ARGData }, { "ARZ", ARZData },
  { "ASN", ASNData }, { "ASP", ASPData }, { "ASH", ASHData },
  { "CYS", CYSData }, { "CYX", CYXData }, { "GLN", GLNData },
  { "GLU", GLUData }, { "GLY", GLYData }, { "GLZ", GLZData },
  { "HID", HIDData }, { "HIE", HIEData }, { "HIP", HIPData },
  { "HIS", HISData }, { "ILE", ILEData }, { "LEU", LEUData },
  { "LYS", LYSData }, { "LYZ", LYZData }, { "MET", METData },
  { "PHE", PHEData }, { "PRO", PROData }, { "PSE", PSEData },
  { "PSM", PSMData }, { "PTM", PTMData }, { "PTY", PTYData },
  { "SER", SERData }, { "THR", THRData }, { "TRP", TRPData },
  { "TYR", TYRData }, { "VAL", VALData }, { "TIP", TIPData },
  { "HOH", HOHData }, { "WAT", WATData }, { "INH", INHData },
  { "UMP", UMPData }, { "HED", HEDData }
};
}
}

#endif