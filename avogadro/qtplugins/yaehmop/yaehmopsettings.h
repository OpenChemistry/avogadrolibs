/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2018 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_YAEHMOPSETTINGS_H
#define AVOGADRO_QTPLUGINS_YAEHMOPSETTINGS_H

#include <QString>

namespace Avogadro {
namespace QtPlugins {

static const char* YAEHMOP_DEFAULT_SPECIAL_KPOINTS = "GM 0 0 0";

struct YaehmopSettings
{
  YaehmopSettings()
    : numBandKPoints(40), specialKPoints(YAEHMOP_DEFAULT_SPECIAL_KPOINTS),
      displayYaehmopInput(false), limitY(false), minY(0.0), maxY(0.0),
      plotFermi(false), fermi(0.0), zeroFermi(false), numDim(3){};

  unsigned long long numBandKPoints;
  QString specialKPoints;
  bool displayYaehmopInput;
  bool limitY;
  double minY;
  double maxY;
  bool plotFermi;
  double fermi;
  bool zeroFermi;
  unsigned short numDim;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_YAEHMOPSETTINGS_H
