/**********************************************************************
  QTAIM - Extension for Quantum Theory of Atoms In Molecules Analysis

  Copyright (C) 2010 Eric C. Brown

  This file is part of the Avogadro molecular editor project.
  For more information, see <http://avogadro.openmolecules.net/>

  Avogadro is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  Avogadro is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
  02110-1301, USA.
**********************************************************************/

#ifndef QTAIMCRITICALPOINTLOCATOR_H
#define QTAIMCRITICALPOINTLOCATOR_H

#include <QDebug>
#include <QList>
#include <QVector3D>
#include <QPair>

#include "qtaimwavefunction.h"
#include "qtaimwavefunctionevaluator.h"
#include "qtaimmathutilities.h"

namespace Avogadro {

  class QTAIMCriticalPointLocator
  {

  public:
    explicit QTAIMCriticalPointLocator(QTAIMWavefunction &wfn);
    void locateNuclearCriticalPoints();
    void locateBondCriticalPoints();

    QList<QVector3D> nuclearCriticalPoints() const { return m_nuclearCriticalPoints; }
    QList<QVector3D> bondCriticalPoints() const { return m_bondCriticalPoints; }
    QList<QVector3D> ringCriticalPoints() const { return m_ringCriticalPoints; }
    QList<QVector3D> cageCriticalPoints() const { return m_cageCriticalPoints; }

    QList<qreal> laplacianAtBondCriticalPoints() const { return m_laplacianAtBondCriticalPoints; }
    QList<qreal> ellipticityAtBondCriticalPoints() const { return m_ellipticityAtBondCriticalPoints; }

    QList<QList<QVector3D> > bondPaths() {return m_bondPaths; }
    QList<QPair<qint64,qint64> > bondedAtoms() {return m_bondedAtoms; }

  private:

    QTAIMWavefunction *m_wfn;

    QList<QVector3D> m_nuclearCriticalPoints;
    QList<QVector3D> m_bondCriticalPoints;
    QList<QVector3D> m_ringCriticalPoints;
    QList<QVector3D> m_cageCriticalPoints;

    QList<qreal> m_laplacianAtBondCriticalPoints;
    QList<qreal> m_ellipticityAtBondCriticalPoints;
    QList<QPair<qint64, qint64> > m_bondedAtoms;
    QList<QList<QVector3D> > m_bondPaths;

    QString temporaryFileName();

  };

} // namespace Avogadro

#endif // QTAIMCRITICALPOINTLOCATOR_H
