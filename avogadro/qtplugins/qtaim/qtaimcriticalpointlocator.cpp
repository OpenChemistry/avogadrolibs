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

#include "qtaimcriticalpointlocator.h"

#include "qtaimlsodaintegrator.h"
#include "qtaimmathutilities.h"
#include "qtaimwavefunctionevaluator.h"

#include <Eigen/Core>

#include <QList>

#include <QtConcurrent/QtConcurrentMap>

#include <QDataStream>
#include <QDir>
#include <QFile>
#include <QTemporaryFile>

#include <QVariant>

#include <QFuture>
#include <QFutureWatcher>
#include <QProgressDialog>

using namespace Eigen;

#define HUGE_REAL_NUMBER 1.e20
#define SMALL_GRADIENT_NORM 1.e-4

namespace Avogadro::QtPlugins {

namespace helper {
template <qint64 ExpectedSignatureV>
QList<QVariant> QTAIMLocateElectronDensityHelper(QList<QVariant> input)
{
  qint64 counter = 0;
  const QString fileName = input.at(counter).toString();
  counter++;
  //    const qint64 nucleus=input.at(counter).toInt(); counter++
  qreal x0 = input.at(counter).toReal();
  counter++;
  qreal y0 = input.at(counter).toReal();
  counter++;
  qreal z0 = input.at(counter).toReal();
  counter++;

  const QVector3D x0y0z0(x0, y0, z0);

  QTAIMWavefunction wfn;
  wfn.loadFromBinaryFile(fileName);

  QTAIMWavefunctionEvaluator eval(wfn);

  /**
    The following logic chain was concatenated into a single statement to remove
    redundant branching, for readability the following table has been included.
    If any of the logic checks do not meet the expected result, the return value
    will be `false`, else it will be `true`.

    logic chain breakdown:
    | Statement | Expected |
    |-----------|----------|
    | eval.electronDensity(x0y0z0) < 1.e-1 | false |
    | eval.electronDensity(xyz) > 1.e-1 | true |
    | eval.gradientOfElectronDensityLaplacian(xyz).norm() < 1.e-3 | true |
    |
    QTAIMMathUtilities::signatureOfASymmetricThreeByThreeMatrix(eval.hessianOfElectronDensityLaplacian(xyz))
    == ExpectedSignatureV | true |
  */

  // Validate initial input to avoid needless costly calculations
  if (eval.electronDensity(Matrix<qreal, 3, 1>(x0, y0, z0)) < 1.e-1) {
    return { false };
  }

  //      QTAIMODEIntegrator
  //      ode(eval,QTAIMODEIntegrator::CMBPMinusThreeGradientInElectronDensityLaplacian);
  QTAIMLSODAIntegrator ode(
    eval,
    QTAIMLSODAIntegrator::CMBPMinusThreeGradientInElectronDensityLaplacian);
  QVector3D result = ode.integrate(x0y0z0);

  Matrix<qreal, 3, 1> xyz(result.x(), result.y(), result.z());

  // since we are using `&&` operator, lazy evaluation will be used
  if (eval.electronDensity(xyz) > 1.e-1 &&
      eval.gradientOfElectronDensityLaplacian(xyz).norm() < 1.e-3 &&
      QTAIMMathUtilities::signatureOfASymmetricThreeByThreeMatrix(
        eval.hessianOfElectronDensityLaplacian(xyz)) == ExpectedSignatureV) {
    return { true, result.x(), result.y(), result.z() };
  }

  return { false };
}

} // namespace helper

QList<QVariant> QTAIMLocateNuclearCriticalPoint(QList<QVariant> input)
{
  const QString fileName = input.at(0).toString();
  const qint64 nucleus = input.at(1).toInt();
  const QVector3D x0y0z0(input.at(2).toReal(), input.at(3).toReal(),
                         input.at(4).toReal());

  QTAIMWavefunction wfn;
  wfn.loadFromBinaryFile(fileName);

  QTAIMWavefunctionEvaluator eval(wfn);

  QVector3D result;

  if (wfn.nuclearCharge(nucleus) < 4) {
    //      QTAIMODEIntegrator
    //      ode(eval,QTAIMODEIntegrator::CMBPMinusThreeGradientInElectronDensity);
    QTAIMLSODAIntegrator ode(
      eval, QTAIMLSODAIntegrator::CMBPMinusThreeGradientInElectronDensity);
    result = ode.integrate(x0y0z0);
  } else {
    result = x0y0z0;
  }

  if (QTAIMMathUtilities::signatureOfASymmetricThreeByThreeMatrix(
        eval.hessianOfElectronDensity(
          Matrix<qreal, 3, 1>(result.x(), result.y(), result.z()))) == -3) {
    return { true, result.x(), result.y(), result.z() };
  }

  return { false };
}

QList<QVariant> QTAIMLocateBondCriticalPoint(QList<QVariant> input)
{
  const QString wfnFileName = input.at(0).toString();
  const QString nuclearCriticalPointsFileName = input.at(1).toString();
  const qint64 nucleusA = input.at(2).toInt();
  const qint64 nucleusB = input.at(3).toInt();
  const QVector3D x0y0z0(input.at(4).toReal(), input.at(5).toReal(),
                         input.at(6).toReal());

  QTAIMWavefunction wfn;
  wfn.loadFromBinaryFile(wfnFileName);

  QList<QVector3D> nuclearCriticalPoints;
  QFile nuclearCriticalPointsFile(nuclearCriticalPointsFileName);
  nuclearCriticalPointsFile.open(QIODevice::ReadOnly);
  QDataStream nuclearCriticalPointsFileIn(&nuclearCriticalPointsFile);
  nuclearCriticalPointsFileIn >> nuclearCriticalPoints;
  nuclearCriticalPointsFile.close();

  QList<QPair<QVector3D, qreal>> betaSpheres;
  for (auto nuclearCriticalPoint : nuclearCriticalPoints) {
    QPair<QVector3D, qreal> thisBetaSphere;
    thisBetaSphere.first = nuclearCriticalPoint;
    thisBetaSphere.second = 0.1;
    betaSpheres.append(thisBetaSphere);
  }

  QTAIMWavefunctionEvaluator eval(wfn);

  QList<QVector3D> ncpList;

  //    QTAIMODEIntegrator
  //    ode(eval,QTAIMODEIntegrator::CMBPMinusOneGradientInElectronDensity);
  QTAIMLSODAIntegrator ode(
    eval, QTAIMLSODAIntegrator::CMBPMinusOneGradientInElectronDensity);
  QVector3D result = ode.integrate(x0y0z0);
  Matrix<qreal, 3, 1> xyz(result.x(), result.y(), result.z());

  if (!(QTAIMMathUtilities::signatureOfASymmetricThreeByThreeMatrix(
          eval.hessianOfElectronDensity(xyz)) == -1) ||
      (eval.gradientOfElectronDensity(xyz)).norm() > SMALL_GRADIENT_NORM) {
    return { false, result.x(), result.y(), result.z() };
  }

  Matrix<qreal, 3, 3> eigenvectorsOfHessian =
    QTAIMMathUtilities::eigenvectorsOfASymmetricThreeByThreeMatrix(
      eval.hessianOfElectronDensity(xyz));
  Matrix<qreal, 3, 1> highestEigenvectorOfHessian(eigenvectorsOfHessian(0, 2),
                                                  eigenvectorsOfHessian(1, 2),
                                                  eigenvectorsOfHessian(2, 2));

  const qreal smallStep = 0.01;

  QVector3D forwardStartingPoint(
    result.x() + smallStep * highestEigenvectorOfHessian(0),
    result.y() + smallStep * highestEigenvectorOfHessian(1),
    result.z() + smallStep * highestEigenvectorOfHessian(2));

  QVector3D backwardStartingPoint(
    result.x() - smallStep * highestEigenvectorOfHessian(0),
    result.y() - smallStep * highestEigenvectorOfHessian(1),
    result.z() - smallStep * highestEigenvectorOfHessian(2));

  //    QTAIMODEIntegrator
  //    forwardODE(eval,QTAIMODEIntegrator::SteepestAscentPathInElectronDensity);
  QTAIMLSODAIntegrator forwardODE(
    eval, QTAIMLSODAIntegrator::SteepestAscentPathInElectronDensity);
  forwardODE.setBetaSpheres(betaSpheres);

  QVector3D forwardEndpoint = forwardODE.integrate(forwardStartingPoint);
  QList<QVector3D> forwardPath = forwardODE.path();

  //    QTAIMODEIntegrator
  //    backwardODE(eval,QTAIMODEIntegrator::SteepestAscentPathInElectronDensity);
  QTAIMLSODAIntegrator backwardODE(
    eval, QTAIMLSODAIntegrator::SteepestAscentPathInElectronDensity);
  backwardODE.setBetaSpheres(betaSpheres);

  QVector3D backwardEndpoint = backwardODE.integrate(backwardStartingPoint);
  QList<QVector3D> backwardPath = backwardODE.path();

  // Find and store the forward and backward nucleus index for pair connection
  // check
  qreal minForwardDistance = HUGE_REAL_NUMBER;
  qreal minBackwardDistance = HUGE_REAL_NUMBER;
  qint64 backwardNucleusIndex = 0;
  qint64 forwardNucleusIndex = 0;

  // cache unchanged points
  const Matrix<qreal, 3, 1> forwardPoint(
    forwardEndpoint.x(), forwardEndpoint.y(), forwardEndpoint.z());
  const Matrix<qreal, 3, 1> backwardPoint(
    backwardEndpoint.x(), backwardEndpoint.y(), backwardEndpoint.z());

  for (qint64 n = 0; n < wfn.numberOfNuclei(); ++n) {
    const Matrix<qreal, 3, 1> wavePoint(wfn.xNuclearCoordinate(n),
                                        wfn.yNuclearCoordinate(n),
                                        wfn.zNuclearCoordinate(n));

    qreal fDistance = QTAIMMathUtilities::distance(forwardPoint, wavePoint);
    qreal bDistance = QTAIMMathUtilities::distance(backwardPoint, wavePoint);

    if (fDistance < minForwardDistance) {
      minForwardDistance = fDistance;
      forwardNucleusIndex = n;
    }
    if (bDistance < minBackwardDistance) {
      minBackwardDistance = bDistance;
      backwardNucleusIndex = n;
    }
  }

  QList<QVariant> value;
  // if statement checks if bond path connects pair
  if ((forwardNucleusIndex == nucleusA && backwardNucleusIndex == nucleusB) ||
      (forwardNucleusIndex == nucleusB && backwardNucleusIndex == nucleusA)) {
    value.append(true);
    value.append(nucleusA);
    value.append(nucleusB);
    value.append(result.x());
    value.append(result.y());
    value.append(result.z());

    const Matrix<qreal, 3, 1> xyz_(result.x(), result.y(), result.z());
    value.append(eval.laplacianOfElectronDensity(xyz_));
    value.append(QTAIMMathUtilities::ellipticityOfASymmetricThreeByThreeMatrix(
      eval.hessianOfElectronDensity(xyz_)));

    value.append(1 + forwardPath.length() + 1 + backwardPath.length() + 1);
    value.append(forwardEndpoint.x());
    for (qint64 i = forwardPath.length() - 1; i >= 0; --i) {
      value.append(forwardPath.at(i).x());
    }
    value.append(result.x());
    for (auto i : backwardPath) {
      value.append(i.x());
    }
    value.append(backwardEndpoint.x());
    value.append(forwardEndpoint.y());
    for (qint64 i = forwardPath.length() - 1; i >= 0; --i) {
      value.append(forwardPath.at(i).y());
    }
    value.append(result.y());
    for (auto i : backwardPath) {
      value.append(i.y());
    }
    value.append(backwardEndpoint.y());
    value.append(forwardEndpoint.z());
    for (qint64 i = forwardPath.length() - 1; i >= 0; --i) {
      value.append(forwardPath.at(i).z());
    }
    value.append(result.z());
    for (auto i : backwardPath) {
      value.append(i.z());
    }
    value.append(backwardEndpoint.z());

  } else {
    value.append(false);
    // for debugging
    value.append(result.x());
    value.append(result.y());
    value.append(result.z());
  }

  return value;
}

QList<QVariant> QTAIMLocateElectronDensitySink(QList<QVariant> input)
{
  /**
    This function acts as a wrapper to consolidate code
    The primary functionality only deviates from other functions in its
    expected value for

    QTAIMMathUtilities::signatureOfASymmetricThreeByThreeMatrix(eval.hessianOfElectronDensityLaplacian(**Integrated
    Point**))

    which is passed in as a template parameter to the helper function.

    At the time of writing this value is -3.
  */
  return helper::QTAIMLocateElectronDensityHelper<-3>(input);
}

QList<QVariant> QTAIMLocateElectronDensitySource(QList<QVariant> input)
{
  /**
    This function acts as a wrapper to consolidate code
    The primary functionality only deviates from other functions in its
    expected value for

    QTAIMMathUtilities::signatureOfASymmetricThreeByThreeMatrix(eval.hessianOfElectronDensityLaplacian(**Integrated
    Point**))

    which is passed in as a template parameter to the helper function.

    At the time of writing this value is 3.
  */
  return helper::QTAIMLocateElectronDensityHelper<3>(input);
}

QTAIMCriticalPointLocator::QTAIMCriticalPointLocator(QTAIMWavefunction& wfn)
{
  m_wfn = &wfn;

  m_nuclearCriticalPoints.clear();
  m_bondCriticalPoints.clear();
  m_ringCriticalPoints.clear();
  m_cageCriticalPoints.clear();

  m_laplacianAtBondCriticalPoints.clear();
  m_ellipticityAtBondCriticalPoints.clear();

  m_bondPaths.clear();
  m_bondedAtoms.clear();

  m_electronDensitySources.clear();
  m_electronDensitySinks.clear();
}

void QTAIMCriticalPointLocator::locateNuclearCriticalPoints()
{

  QString tempFileName = QTAIMCriticalPointLocator::temporaryFileName();

  QList<QList<QVariant>> inputList;

  const qint64 numberOfNuclei = m_wfn->numberOfNuclei();

  for (qint64 n = 0; n < numberOfNuclei; ++n) {
    QList<QVariant> input;
    input.append(tempFileName);
    input.append(n);
    input.append(m_wfn->xNuclearCoordinate(n));
    input.append(m_wfn->yNuclearCoordinate(n));
    input.append(m_wfn->zNuclearCoordinate(n));

    inputList.append(input);
  }

  m_wfn->saveToBinaryFile(tempFileName);

  QProgressDialog dialog;
  dialog.setWindowTitle("QTAIM");
  dialog.setLabelText(QString("Nuclear Critical Points Search"));

  QFutureWatcher<QList<QVariant>> futureWatcher;
  QObject::connect(&futureWatcher, SIGNAL(finished()), &dialog, SLOT(reset()));
  QObject::connect(&dialog, SIGNAL(canceled()), &futureWatcher, SLOT(cancel()));
  QObject::connect(&futureWatcher, SIGNAL(progressRangeChanged(int, int)),
                   &dialog, SLOT(setRange(int, int)));
  QObject::connect(&futureWatcher, SIGNAL(progressValueChanged(int)), &dialog,
                   SLOT(setValue(int)));

  QFuture<QList<QVariant>> future =
    QtConcurrent::mapped(inputList, QTAIMLocateNuclearCriticalPoint);
  futureWatcher.setFuture(future);
  dialog.exec();
  futureWatcher.waitForFinished();

  QList<QList<QVariant>> results;
  if (futureWatcher.future().isCanceled()) {
    results.clear();
  } else {
    results = future.results();
  }

  QFile file;
  file.remove(tempFileName);

  for (const auto& n : results) {
    if (n.at(0).toBool()) {
      QVector3D result(n.at(1).toReal(), n.at(2).toReal(), n.at(3).toReal());

      m_nuclearCriticalPoints.append(result);
    }
  }
}

void QTAIMCriticalPointLocator::locateBondCriticalPoints()
{

  if (m_nuclearCriticalPoints.length() < 1) {
    return;
  }

  const qint64 numberOfNuclei = m_wfn->numberOfNuclei();

  if (numberOfNuclei < 2) {
    return;
  }

  QString tempFileName = QTAIMCriticalPointLocator::temporaryFileName();

  QString nuclearCriticalPointsFileName =
    QTAIMCriticalPointLocator::temporaryFileName();
  QFile nuclearCriticalPointsFile(nuclearCriticalPointsFileName);
  nuclearCriticalPointsFile.open(QIODevice::WriteOnly);
  QDataStream nuclearCriticalPointsOut(&nuclearCriticalPointsFile);
  nuclearCriticalPointsOut << m_nuclearCriticalPoints;
  nuclearCriticalPointsFile.close();

  QList<QList<QVariant>> inputList;

  for (qint64 M = 0; M < numberOfNuclei - 1; ++M) {
    for (qint64 N = M + 1; N < numberOfNuclei; ++N) {

      const qreal distanceCutoff = 8.0;

      Matrix<qreal, 3, 1> a;
      Matrix<qreal, 3, 1> b;

      a << m_wfn->xNuclearCoordinate(M), m_wfn->yNuclearCoordinate(M),
        m_wfn->zNuclearCoordinate(M);
      b << m_wfn->xNuclearCoordinate(N), m_wfn->yNuclearCoordinate(N),
        m_wfn->zNuclearCoordinate(N);

      if (QTAIMMathUtilities::distance(a, b) < distanceCutoff) {
        QVector3D x0y0z0(
          (m_wfn->xNuclearCoordinate(M) + m_wfn->xNuclearCoordinate(N)) / 2.0,
          (m_wfn->yNuclearCoordinate(M) + m_wfn->yNuclearCoordinate(N)) / 2.0,
          (m_wfn->zNuclearCoordinate(M) + m_wfn->zNuclearCoordinate(N)) / 2.0);

        QList<QVariant> input;
        input.append(tempFileName);
        input.append(nuclearCriticalPointsFileName);
        input.append(M);
        input.append(N);
        input.append(x0y0z0.x());
        input.append(x0y0z0.y());
        input.append(x0y0z0.z());

        inputList.append(input);
      }
    } // end N
  }   // end M

  m_wfn->saveToBinaryFile(tempFileName);

  QProgressDialog dialog;
  dialog.setWindowTitle("QTAIM");
  dialog.setLabelText(QString("Bond Critical Points Search"));

  QFutureWatcher<QList<QVariant>> futureWatcher;
  QObject::connect(&futureWatcher, SIGNAL(finished()), &dialog, SLOT(reset()));
  QObject::connect(&dialog, SIGNAL(canceled()), &futureWatcher, SLOT(cancel()));
  QObject::connect(&futureWatcher, SIGNAL(progressRangeChanged(int, int)),
                   &dialog, SLOT(setRange(int, int)));
  QObject::connect(&futureWatcher, SIGNAL(progressValueChanged(int)), &dialog,
                   SLOT(setValue(int)));

  QFuture<QList<QVariant>> future =
    QtConcurrent::mapped(inputList, QTAIMLocateBondCriticalPoint);
  ;
  futureWatcher.setFuture(future);
  dialog.exec();
  futureWatcher.waitForFinished();

  QList<QList<QVariant>> results;
  if (futureWatcher.future().isCanceled()) {
    results.clear();
  } else {
    results = future.results();
  }

  QFile file;
  file.remove(tempFileName);
  file.remove(nuclearCriticalPointsFileName);

  for (const auto& thisCriticalPoint : results) {
    bool success = thisCriticalPoint.at(0).toBool();

    if (success) {
      QPair<qint64, qint64> bondedAtoms_;
      bondedAtoms_.first = thisCriticalPoint.at(1).toInt();
      bondedAtoms_.second = thisCriticalPoint.at(2).toInt();
      m_bondedAtoms.append(bondedAtoms_);

      QVector3D coordinates(thisCriticalPoint.at(3).toReal(),
                            thisCriticalPoint.at(4).toReal(),
                            thisCriticalPoint.at(5).toReal());

      m_bondCriticalPoints.append(coordinates);

      m_laplacianAtBondCriticalPoints.append(thisCriticalPoint.at(6).toReal());
      m_ellipticityAtBondCriticalPoints.append(
        thisCriticalPoint.at(7).toReal());
      qint64 pathLength = thisCriticalPoint.at(8).toInt();

      QList<QVector3D> bondPath;
      for (qint64 j = 0; j < pathLength; ++j) {
        QVector3D pathPoint(
          thisCriticalPoint.at(9 + j).toReal(),
          thisCriticalPoint.at(9 + j + pathLength).toReal(),
          thisCriticalPoint.at(9 + j + 2 * pathLength).toReal());

        bondPath.append(pathPoint);
      }

      m_bondPaths.append(bondPath);
    }
  }
}

void QTAIMCriticalPointLocator::locateElectronDensitySources()
{

  QString tempFileName = QTAIMCriticalPointLocator::temporaryFileName();

  QList<QList<QVariant>> inputList;

  qreal xmin, ymin, zmin;
  qreal xmax, ymax, zmax;
  qreal xstep, ystep, zstep;

  // TODO: if only we were using Eigen data structures...
  QList<qreal> xNuclearCoordinates;
  QList<qreal> yNuclearCoordinates;
  QList<qreal> zNuclearCoordinates;

  for (qint64 i = 0; i < m_wfn->numberOfNuclei(); ++i) {
    xNuclearCoordinates.append(m_wfn->xNuclearCoordinate(i));
    yNuclearCoordinates.append(m_wfn->yNuclearCoordinate(i));
    zNuclearCoordinates.append(m_wfn->zNuclearCoordinate(i));
  }

  xmin = xNuclearCoordinates.first();
  xmax = xNuclearCoordinates.first();
  for (qint64 i = 1; i < m_wfn->numberOfNuclei(); ++i) {
    if (xNuclearCoordinates.at(i) < xmin) {
      xmin = xNuclearCoordinates.at(i);
    }
    if (xNuclearCoordinates.at(i) > xmax) {
      xmax = xNuclearCoordinates.at(i);
    }
  }

  ymin = yNuclearCoordinates.first();
  ymax = yNuclearCoordinates.first();
  for (qint64 i = 1; i < yNuclearCoordinates.count(); ++i) {
    if (yNuclearCoordinates.at(i) < ymin) {
      ymin = yNuclearCoordinates.at(i);
    }
    if (yNuclearCoordinates.at(i) > ymax) {
      ymax = yNuclearCoordinates.at(i);
    }
  }

  zmin = zNuclearCoordinates.first();
  zmax = zNuclearCoordinates.first();
  for (qint64 i = 1; i < zNuclearCoordinates.count(); ++i) {
    if (zNuclearCoordinates.at(i) < zmin) {
      zmin = zNuclearCoordinates.at(i);
    }
    if (zNuclearCoordinates.at(i) > zmax) {
      zmax = zNuclearCoordinates.at(i);
    }
  }

  xmin = -2.0 + xmin;
  ymin = -2.0 + ymin;
  zmin = -2.0 + zmin;

  xmax = 2.0 + xmax;
  ymax = 2.0 + ymax;
  zmax = 2.0 + zmax;

  xstep = ystep = zstep = 0.5;

  for (qreal x = xmin; x < xmax + xstep; x = x + xstep) {
    for (qreal y = ymin; y < ymax + ystep; y = y + ystep) {
      for (qreal z = zmin; z < zmax + zstep; z = z + zstep) {
        QList<QVariant> input;
        input.append(tempFileName);
        //          input.append( n );
        input.append(x);
        input.append(y);
        input.append(z);

        inputList.append(input);
      }
    }
  }

  m_wfn->saveToBinaryFile(tempFileName);

  QProgressDialog dialog;
  dialog.setWindowTitle("QTAIM");
  dialog.setLabelText(QString("Electron Density Sources Search"));

  QFutureWatcher<QList<QVariant>> futureWatcher;
  QObject::connect(&futureWatcher, SIGNAL(finished()), &dialog, SLOT(reset()));
  QObject::connect(&dialog, SIGNAL(canceled()), &futureWatcher, SLOT(cancel()));
  QObject::connect(&futureWatcher, SIGNAL(progressRangeChanged(int, int)),
                   &dialog, SLOT(setRange(int, int)));
  QObject::connect(&futureWatcher, SIGNAL(progressValueChanged(int)), &dialog,
                   SLOT(setValue(int)));

  QFuture<QList<QVariant>> future =
    QtConcurrent::mapped(inputList, QTAIMLocateElectronDensitySource);
  futureWatcher.setFuture(future);
  dialog.exec();
  futureWatcher.waitForFinished();

  QList<QList<QVariant>> results;
  if (futureWatcher.future().isCanceled()) {
    results.clear();
  } else {
    results = future.results();
  }

  QFile file;
  file.remove(tempFileName);

  for (const auto& n : results) {
    if (n.at(0).toBool()) {
      qreal x = n.at(1).toReal();
      qreal y = n.at(2).toReal();
      qreal z = n.at(3).toReal();

      if ((xmin < x && x < xmax) && (ymin < y && y < ymax) &&
          (zmin < z && z < zmax)) {
        QVector3D result(x, y, z);

        qreal smallestDistance = HUGE_REAL_NUMBER;

        for (auto m_electronDensitySource : m_electronDensitySources) {

          Matrix<qreal, 3, 1> a(x, y, z);
          Matrix<qreal, 3, 1> b(m_electronDensitySource.x(),
                                m_electronDensitySource.y(),
                                m_electronDensitySource.z());

          qreal distance = QTAIMMathUtilities::distance(a, b);

          if (distance < smallestDistance) {
            smallestDistance = distance;
          }
        }

        if (smallestDistance > 1.e-2) {
          m_electronDensitySources.append(result);
        }
      }
    }
  }
  //    qDebug() << "SOURCES" << m_electronDensitySources;
}

void QTAIMCriticalPointLocator::locateElectronDensitySinks()
{

  QString tempFileName = QTAIMCriticalPointLocator::temporaryFileName();

  QList<QList<QVariant>> inputList;

  qreal xmin, ymin, zmin;
  qreal xmax, ymax, zmax;
  qreal xstep, ystep, zstep;

  // TODO: if only we were using Eigen data structures...
  QList<qreal> xNuclearCoordinates;
  QList<qreal> yNuclearCoordinates;
  QList<qreal> zNuclearCoordinates;

  for (qint64 i = 0; i < m_wfn->numberOfNuclei(); ++i) {
    xNuclearCoordinates.append(m_wfn->xNuclearCoordinate(i));
    yNuclearCoordinates.append(m_wfn->yNuclearCoordinate(i));
    zNuclearCoordinates.append(m_wfn->zNuclearCoordinate(i));
  }

  xmin = xNuclearCoordinates.first();
  xmax = xNuclearCoordinates.first();
  for (qint64 i = 1; i < m_wfn->numberOfNuclei(); ++i) {
    if (xNuclearCoordinates.at(i) < xmin) {
      xmin = xNuclearCoordinates.at(i);
    }
    if (xNuclearCoordinates.at(i) > xmax) {
      xmax = xNuclearCoordinates.at(i);
    }
  }

  ymin = yNuclearCoordinates.first();
  ymax = yNuclearCoordinates.first();
  for (qint64 i = 1; i < yNuclearCoordinates.count(); ++i) {
    if (yNuclearCoordinates.at(i) < ymin) {
      ymin = yNuclearCoordinates.at(i);
    }
    if (yNuclearCoordinates.at(i) > ymax) {
      ymax = yNuclearCoordinates.at(i);
    }
  }

  zmin = zNuclearCoordinates.first();
  zmax = zNuclearCoordinates.first();
  for (qint64 i = 1; i < zNuclearCoordinates.count(); ++i) {
    if (zNuclearCoordinates.at(i) < zmin) {
      zmin = zNuclearCoordinates.at(i);
    }
    if (zNuclearCoordinates.at(i) > zmax) {
      zmax = zNuclearCoordinates.at(i);
    }
  }

  xmin = -2.0 + xmin;
  ymin = -2.0 + ymin;
  zmin = -2.0 + zmin;

  xmax = 2.0 + xmax;
  ymax = 2.0 + ymax;
  zmax = 2.0 + zmax;

  xstep = ystep = zstep = 0.5;

  for (qreal x = xmin; x < xmax + xstep; x = x + xstep) {
    for (qreal y = ymin; y < ymax + ystep; y = y + ystep) {
      for (qreal z = zmin; z < zmax + zstep; z = z + zstep) {
        QList<QVariant> input;
        input.append(tempFileName);
        //          input.append( n );
        input.append(x);
        input.append(y);
        input.append(z);

        inputList.append(input);
      }
    }
  }

  m_wfn->saveToBinaryFile(tempFileName);

  QProgressDialog dialog;
  dialog.setWindowTitle("QTAIM");
  dialog.setLabelText(QString("Electron Density Sinks Search"));

  QFutureWatcher<QList<QVariant>> futureWatcher;
  QObject::connect(&futureWatcher, SIGNAL(finished()), &dialog, SLOT(reset()));
  QObject::connect(&dialog, SIGNAL(canceled()), &futureWatcher, SLOT(cancel()));
  QObject::connect(&futureWatcher, SIGNAL(progressRangeChanged(int, int)),
                   &dialog, SLOT(setRange(int, int)));
  QObject::connect(&futureWatcher, SIGNAL(progressValueChanged(int)), &dialog,
                   SLOT(setValue(int)));

  QFuture<QList<QVariant>> future =
    QtConcurrent::mapped(inputList, QTAIMLocateElectronDensitySink);
  futureWatcher.setFuture(future);
  dialog.exec();
  futureWatcher.waitForFinished();

  QList<QList<QVariant>> results;
  if (futureWatcher.future().isCanceled()) {
    results.clear();
  } else {
    results = future.results();
  }

  QFile file;
  file.remove(tempFileName);

  for (const auto& n : results) {
    if (n.at(0).toBool()) {
      qreal x = n.at(1).toReal();
      qreal y = n.at(2).toReal();
      qreal z = n.at(3).toReal();

      if ((xmin < x && x < xmax) && (ymin < y && y < ymax) &&
          (zmin < z && z < zmax)) {
        QVector3D result(x, y, z);

        qreal smallestDistance = HUGE_REAL_NUMBER;

        for (auto m_electronDensitySink : m_electronDensitySinks) {

          Matrix<qreal, 3, 1> a(x, y, z);
          Matrix<qreal, 3, 1> b(m_electronDensitySink.x(),
                                m_electronDensitySink.y(),
                                m_electronDensitySink.z());

          qreal distance = QTAIMMathUtilities::distance(a, b);

          if (distance < smallestDistance) {
            smallestDistance = distance;
          }
        }

        if (smallestDistance > 1.e-2) {
          m_electronDensitySinks.append(result);
        }
      }
    }
  }
  //    qDebug() << "SINKS" << m_electronDensitySinks;
}

QString QTAIMCriticalPointLocator::temporaryFileName()
{
  QTemporaryFile temporaryFile;
  temporaryFile.open();
  QString tempFileName = temporaryFile.fileName();
  temporaryFile.close();
  temporaryFile.remove();

  // wait for temporary file to be deleted
  QDir dir;
  do {
    // Nothing
  } while (dir.exists(tempFileName));

  return tempFileName;
}

} // namespace Avogadro::QtPlugins
