/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
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
