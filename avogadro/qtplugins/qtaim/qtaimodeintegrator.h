/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright (C) 2010 Eric C. Brown

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef QTAIMODEINTEGRATOR_H
#define QTAIMODEINTEGRATOR_H

#include <QDebug>
#include <QList>
#include <QPair>
#include <QVector3D>

#include <Eigen/Core>

#include "qtaimmathutilities.h"
#include "qtaimwavefunction.h"
#include "qtaimwavefunctionevaluator.h"

namespace Avogadro {
namespace QtPlugins {

class QTAIMODEIntegrator
{

public:
  enum
  {
    SteepestAscentPathInElectronDensity = 0,
    CMBPMinusThreeGradientInElectronDensity = 1,
    CMBPMinusOneGradientInElectronDensity = 2,
    CMBPPlusOneGradientInElectronDensity = 3,
    CMBPPlusThreeGradientInElectronDensity = 4,
    CMBPMinusThreeGradientInElectronDensityLaplacian = 5,
    CMBPMinusOneGradientInElectronDensityLaplacian = 6,
    CMBPPlusOneGradientInElectronDensityLaplacian = 7,
    CMBPPlusThreeGradientInElectronDensityLaplacian = 8
  };

  explicit QTAIMODEIntegrator(QTAIMWavefunctionEvaluator& eval,
                              const qint64 mode);

  QVector3D integrate(QVector3D x0y0z0);

  qint64 status() const { return m_status; }
  const QList<QVector3D> path() const { return m_path; }

  void setBetaSpheres(QList<QPair<QVector3D, qreal>> betaSpheres)
  {
    m_betaSpheres = betaSpheres;
  }
  qint64 associatedSphere() const { return m_associatedSphere; }

private:
  QTAIMWavefunctionEvaluator* m_eval;
  qint64 m_mode;

  qint64 m_status;
  QList<QVector3D> m_path;

  QList<QPair<QVector3D, qreal>> m_betaSpheres;
  qint64 m_associatedSphere;

  // ODE integrator
  qreal r8_abs(qreal x);
  qreal r8_epsilon();
  void r8_fehl(qint64 neqn, qreal y[], qreal t, qreal h, qreal yp[], qreal f1[],
               qreal f2[], qreal f3[], qreal f4[], qreal f5[], qreal s[]);
  qreal r8_max(qreal x, qreal y);
  qreal r8_min(qreal x, qreal y);
  qint64 r8_rkf45(qint64 neqn, qreal y[], qreal yp[], qreal* t, qreal tout,
                  qreal* relerr, qreal abserr, qint64 flag);
  qreal r8_sign(qreal x);

  void r8_f(qreal t, qreal y[], qreal yp[]);

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

} // namespace QtPlugins
} // namespace Avogadro

#endif // QTAIMODEINTEGRATOR_H
