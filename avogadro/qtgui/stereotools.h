/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_STEREOTOOLS_H
#define AVOGADRO_QTGUI_STEREOTOOLS_H

#include "avogadroqtguiexport.h"

#include <avogadro/core/avogadrocore.h>

namespace Avogadro::QtGui {

class RWMolecule;

enum class StereoInversionResult
{
  Success = 0,
  InvalidAtom,
  NonCarbonCenter,
  NonTetrahedralCenter,
  UnsupportedBondOrders,
  NoMovableSubstituent,
  DegenerateGeometry
};

class AVOGADROQTGUI_EXPORT StereoTools
{
public:
  static StereoInversionResult invertTetrahedralCenter(RWMolecule& molecule,
                                                       Index atomId);
};

} // namespace Avogadro::QtGui

#endif // AVOGADRO_QTGUI_STEREOTOOLS_H
