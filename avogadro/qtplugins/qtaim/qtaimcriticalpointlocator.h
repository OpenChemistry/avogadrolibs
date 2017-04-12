/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2010 Eric C. Brown

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef QTAIMCRITICALPOINTLOCATOR_H
#define QTAIMCRITICALPOINTLOCATOR_H

#include <QDebug>
#include <QList>
#include <QPair>
#include <QVector3D>

#include "qtaimmathutilities.h"
#include "qtaimwavefunction.h"
#include "qtaimwavefunctionevaluator.h"

namespace Avogadro {
namespace QtPlugins {

class QTAIMCriticalPointLocator
{

public:
  explicit QTAIMCriticalPointLocator(QTAIMWavefunction& wfn);
  void locateNuclearCriticalPoints();
  void locateBondCriticalPoints();

  void locateElectronDensitySources();
  void locateElectronDensitySinks();

  QList<QVector3D> nuclearCriticalPoints() const
  {
    return m_nuclearCriticalPoints;
  }
  QList<QVector3D> bondCriticalPoints() const { return m_bondCriticalPoints; }
  QList<QVector3D> ringCriticalPoints() const { return m_ringCriticalPoints; }
  QList<QVector3D> cageCriticalPoints() const { return m_cageCriticalPoints; }

  QList<qreal> laplacianAtBondCriticalPoints() const
  {
    return m_laplacianAtBondCriticalPoints;
  }
  QList<qreal> ellipticityAtBondCriticalPoints() const
  {
    return m_ellipticityAtBondCriticalPoints;
  }

  QList<QList<QVector3D>> bondPaths() { return m_bondPaths; }
  QList<QPair<qint64, qint64>> bondedAtoms() { return m_bondedAtoms; }

  QList<QVector3D> electronDensitySources() const
  {
    return m_electronDensitySources;
  }
  QList<QVector3D> electronDensitySinks() const
  {
    return m_electronDensitySinks;
  }

private:
  QTAIMWavefunction* m_wfn;

  QList<QVector3D> m_nuclearCriticalPoints;
  QList<QVector3D> m_bondCriticalPoints;
  QList<QVector3D> m_ringCriticalPoints;
  QList<QVector3D> m_cageCriticalPoints;

  QList<qreal> m_laplacianAtBondCriticalPoints;
  QList<qreal> m_ellipticityAtBondCriticalPoints;
  QList<QPair<qint64, qint64>> m_bondedAtoms;
  QList<QList<QVector3D>> m_bondPaths;

  QList<QVector3D> m_electronDensitySources;
  QList<QVector3D> m_electronDensitySinks;

  QString temporaryFileName();
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // QTAIMCRITICALPOINTLOCATOR_H
