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

#include "spacegroups.h"
#include <iostream>
#include <string>
#include <vector>


using Avogadro::Core::SpaceGroups;
namespace Avogadro {
namespace Core {

  std::string SpaceGroups::getInternational(int hallNumber)
  {
    std::string Int(spacegroup_types[hallNumber].international);
    return Int;
  }

  std::string SpaceGroups::getInternationalFull(int hallNumber)
  {
    std::string Int(spacegroup_types[hallNumber].international_full);
    return Int;
  }

  std::string SpaceGroups::getInternationalShort(int hallNumber)
  {
    std::string Int(spacegroup_types[hallNumber].international_short);
    return Int;
  }

  std::string SpaceGroups::getBravais(int hallNumber)
  {
    std::string Int(1,spacegroup_types[hallNumber].international[0]);
    return Int;
  }

  std::string SpaceGroups::getSchoenflies(int hallNumber)
  {
    std::string schoenflies(spacegroup_types[hallNumber].schoenflies);
    return schoenflies;
  }

  int SpaceGroups::getNumber(int hallNumber)
  {
    int number(spacegroup_types[hallNumber].number);
    return number;
  }

  std::string SpaceGroups::getHallSymbol(int hallNumber)
  {
    std::string hallSymbol(spacegroup_types[hallNumber].hall_symbol);
    return hallSymbol;
  }

  std::string SpaceGroups::getSetting(int hallNumber)
  {
    std::string setting(spacegroup_types[hallNumber].setting);
    return setting;
  }

  std::string SpaceGroups::getCrystalSystem(int hallNumber)
  {
    crystalSystem sys = spacegroup_types[hallNumber].holohedry;
    std::string sysString;
    switch(sys)
    {
      case NONE:
        sysString = "None";
        break;
      case TRICLI:
        sysString = "Triclinic";
        break;
      case MONOCLI:
        sysString = "Monoclinic";
        break;
      case ORTHO:
        sysString = "Orthorhombic";
        break;
      case TETRA:
        sysString = "Tetragonal";
        break;
      case TRIGO:
        sysString = "Trigonal";
        break;
      case RHOMB:
        sysString = "Rhombohedral";
        break;
      case HEXA:
        sysString = "Hexagonal";
        break;
      case CUBIC:
        sysString = "Cubic";
        break;
    }

    return sysString;
  }

  void SpaceGroups::describeSpaceGroup(int hallNumber)
  {
    std::string shortSymbol = getInternationalShort(hallNumber);
    std::string fullSymbol  = getInternationalFull(hallNumber);
    std::string crsytal     = getCrystalSystem(hallNumber);
    int number              = getNumber(hallNumber);
    std::string schoenflies  = getSchoenflies(hallNumber);
    std::string setting     = getSetting(hallNumber);

    std::cout <<
      "Short International Symbol:" << std::endl
      << "  " << shortSymbol << std::endl
      << "Schoenflies symbol:" << std::endl
      << "  " << schoenflies << std::endl
      << "Space group number:" << std::endl
      << "  " << number << std::endl
      << "Full International Symbol:" << std::endl
      << "  " << fullSymbol << std::endl
      << "Setting:" << std::endl
      << "  " << setting << std::endl;


  }

  std::vector<SpaceGroups::crystalSystem> SpaceGroups::getCrystalArray()
  {
    std::vector<crystalSystem> crystals;
    crystals.push_back(TRICLI);
    crystals.push_back(MONOCLI);
    crystals.push_back(ORTHO);
    crystals.push_back(TETRA);
    crystals.push_back(TRIGO);
    crystals.push_back(RHOMB);
    crystals.push_back(HEXA);
    crystals.push_back(CUBIC);

    return crystals;

  }
  std::string SpaceGroups::getCrystalString(crystalSystem crystal)
  {
    std::string sysString;
    switch(crystal)
    {
      case NONE:
        sysString = "None";
        break;
      case TRICLI:
        sysString = "Triclinic";
        break;
      case MONOCLI:
        sysString = "Monoclinic";
        break;
      case ORTHO:
        sysString = "Orthorhombic";
        break;
      case TETRA:
        sysString = "Tetragonal";
        break;
      case TRIGO:
        sysString = "Trigonal";
        break;
      case RHOMB:
        sysString = "Rhombohedral";
        break;
      case HEXA:
        sysString = "Hexagonal";
        break;
      case CUBIC:
        sysString = "Cubic";
        break;
    }

    return sysString;
  }

  std::vector<std::string> SpaceGroups::getBravaisArray(crystalSystem crystal)
  {
    std::vector<std::string> bravais;
    for (int hall=0;hall < 530;hall++)
      if (spacegroup_types[hall].holohedry == crystal)
      {
        bravais.push_back(getBravais(hall));
      }
    sort(bravais.begin(), bravais.end());
    bravais.erase(unique(bravais.begin(), bravais.end()), bravais.end());

    return bravais;
  }

  std::vector<std::string> SpaceGroups::getIntSymbolArray(crystalSystem crystal, std::string bravais)
  {
    std::vector<std::string> IntSymbol;
    for(int hall=0;hall<530;hall++)
    {
      if (spacegroup_types[hall].holohedry == crystal)
      {
        if(getBravais(hall) == bravais)
        {
          IntSymbol.push_back(getInternationalShort(hall));
        }
      }
    }
    sort(IntSymbol.begin(), IntSymbol.end());
    IntSymbol.erase(unique(IntSymbol.begin(), IntSymbol.end()), IntSymbol.end());

    return IntSymbol;
  }

  /*Array<std::string> SpaceGroups::getSettingArray(int intNumber)
  {
  }*/




} // namespace Core
} // namespace Avogadro
