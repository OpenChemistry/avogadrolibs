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

#ifndef QTAIMODEINTEGRATOR_H
#define QTAIMODEINTEGRATOR_H

#include <QDebug>
#include <QList>
#include <QVector3D>
#include <QPair>

#include <Eigen/Core>

#include "qtaimwavefunction.h"
#include "qtaimwavefunctionevaluator.h"
#include "qtaimmathutilities.h"

namespace Avogadro {

  class QTAIMODEIntegrator
  {

  public:
    enum
    {
      SteepestAscentPathInElectronDensity=0,
      CMBPMinusThreeGradientInElectronDensity=1,
      CMBPMinusOneGradientInElectronDensity=2,
      CMBPPlusOneGradientInElectronDensity=3,
      CMBPPlusThreeGradientInElectronDensity=4,
      CMBPMinusThreeGradientInElectronDensityLaplacian=5,
      CMBPMinusOneGradientInElectronDensityLaplacian=6,
      CMBPPlusOneGradientInElectronDensityLaplacian=7,
      CMBPPlusThreeGradientInElectronDensityLaplacian=8
                                                    };

    explicit QTAIMODEIntegrator(QTAIMWavefunctionEvaluator &eval, const qint64 mode);

    QVector3D integrate(QVector3D x0y0z0);

    const qint64 status() const { return m_status; }
    const QList<QVector3D> path() const { return m_path; }

    void setBetaSpheres( QList<QPair<QVector3D,qreal> > betaSpheres ) { m_betaSpheres = betaSpheres; }
    const qint64 associatedSphere() const { return m_associatedSphere; }

  private:

    QTAIMWavefunctionEvaluator *m_eval;
    qint64 m_mode;

    qint64 m_status;
    QList<QVector3D> m_path;

    QList<QPair<QVector3D,qreal> > m_betaSpheres;
    qint64 m_associatedSphere;

    // ODE integrator
    qreal r8_abs ( qreal x );
    qreal r8_epsilon ( );
    void r8_fehl ( qint64 neqn,
                   qreal y[], qreal t, qreal h, qreal yp[], qreal f1[], qreal f2[], qreal f3[],
                   qreal f4[], qreal f5[], qreal s[] );
    qreal r8_max ( qreal x, qreal y );
    qreal r8_min ( qreal x, qreal y );
    qint64 r8_rkf45 ( qint64 neqn,
                      qreal y[], qreal yp[], qreal *t, qreal tout, qreal *relerr, qreal abserr,
                      qint64 flag );
    qreal r8_sign ( qreal x );

    void r8_f ( qreal t, qreal y[], qreal yp[]  );

    qreal abserr_save;
    qint64 flag_save;
    qreal h;
    qint64 init;
    qint64 kflag;
    qint64 kop;
    qint64 nfe;
    qreal relerr_save;
    qreal remin;

  };

} // namespace Avogadro

#endif // QTAIMODEINTEGRATOR_H
