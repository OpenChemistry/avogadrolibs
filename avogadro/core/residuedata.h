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

ResidueData alaData("ALA",
  // Atoms
  { "CA", "N", "CB", "C", "O" },
  // Single bonds
  { 
    { "CA", "N" },
    { "CA", "CB" },
    { "CA", "C" },
    { "N", "H" },
    { "N", "HN" },
    { "HA", "CA" },
    { "HB1", "CB" },
    { "HB2", "CB" },
    { "HB3", "CB" } 
  },
  // Double bonds
  { { "C", "O" } });

ResidueData leuData("LEU",
  // Atoms
  { "CA", "N", "CB", "C", "O", "CG", "CD1", "CD2" },
  // Single bonds
  {
    { "CA", "N" },
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
    { "HG", "CG" },
  },
  // Double bonds
  { { "C", "O" } });

std::map<std::string, ResidueData> residueDict = { 
  { "ALA", alaData },
  { "LEU", leuData } 
};

}
}

#endif