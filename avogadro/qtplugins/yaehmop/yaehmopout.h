/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_YAEHMOP_OUT_H
#define AVOGADRO_QTPLUGINS_YAEHMOP_OUT_H

#include <QString>
#include <QVector>

#include <avogadro/core/vector.h>

namespace Avogadro {
namespace QtPlugins {

typedef struct
{
  QString label;
  Vector3 coords;
} specialKPoint;

// Static class for Yaehmop output
class YaehmopOut
{
public:
  // Pass the yaehmop output in as 'data'. It would be faster if this only
  // included the section from BAND_DATA to END_BAND_DATA, but it is not
  // necessary. This sets bands, kpoints, and specialKPoints to be the
  // bands, the kpoints, and the special k points. Returns true if the
  // read was successful, and false if the read failed
  static bool readBandData(const QString& data, QVector<QVector<double>>& bands,
                           QVector<Vector3>& kpoints,
                           QVector<specialKPoint>& specialKPoints);
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_YAEHMOPOUT_H
