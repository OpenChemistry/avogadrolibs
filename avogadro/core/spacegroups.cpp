/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2016 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "spacegroupdata.h"
#include "spacegroups.h"

namespace Avogadro {
namespace Core {

SpaceGroups::SpaceGroups()
{
}

SpaceGroups::~SpaceGroups()
{
}

CrystalSystem SpaceGroups::crystalSystem(unsigned short hallNumber)
{
  if (hallNumber == 1 || hallNumber == 2)
    return Triclinic;
  if (hallNumber >= 3 && hallNumber <= 107)
    return Monoclinic;
  if (hallNumber >= 108 && hallNumber <= 348)
    return Orthorhombic;
  if (hallNumber >= 349 && hallNumber <= 429)
    return Tetragonal;
  if (hallNumber >= 430 && hallNumber <= 461) {
    // 14 of these are rhombohedral and the rest are trigonal
    switch (hallNumber) {
    case 433:
    case 434:
    case 436:
    case 437:
    case 444:
    case 445:
    case 450:
    case 451:
    case 452:
    case 453:
    case 458:
    case 459:
    case 460:
    case 461:
      return Rhombohedral;
    default:
      return Trigonal;
    }
  }
  if (hallNumber >= 462 && hallNumber <= 488)
    return Hexagonal;
  if (hallNumber >= 489 && hallNumber <= 530)
    return Cubic;
  // hallNumber must be 0 or > 531
  return None;
  //for (unsigned short i = 0; i < hallNumberCount; ++i)
}

unsigned short SpaceGroups::internationalNumber(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_international_number[hallNumber];
  else
    return space_group_international_number[0];
}

const char * SpaceGroups::schoenflies(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_schoenflies[hallNumber];
  else
    return space_group_schoenflies[0];
}

const char * SpaceGroups::hallSymbol(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_hall_symbol[hallNumber];
  else
    return space_group_hall_symbol[0];
}

const char * SpaceGroups::international(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_international[hallNumber];
  else
    return space_group_international[0];
}

const char * SpaceGroups::internationalFull(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_international_full[hallNumber];
  else
    return space_group_international_full[0];
}

const char * SpaceGroups::internationalShort(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_international_short[hallNumber];
  else
    return space_group_international_short[0];
}

const char * SpaceGroups::setting(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_setting[hallNumber];
  else
    return space_group_setting[0];
}

} // end Core namespace
} // end Avogadro namespace
