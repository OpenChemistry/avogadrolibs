/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2010 Eric C. Brown
  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "qtaimextension.h"

#include <avogadro/qtgui/molecule.h>

#include <QAction>

#include <QDebug>
#include <QDir>
#include <QFileDialog>
#include <QList>
#include <QPair>
#include <QString>
#include <QVector3D>

#include <QThread>

#include "qtaimcriticalpointlocator.h"
#include "qtaimcubature.h"
#include "qtaimwavefunction.h"
#include "qtaimwavefunctionevaluator.h"

#include <QTime>

using namespace std;
using namespace Eigen;

namespace Avogadro {
namespace QtPlugins {

enum QTAIMExtensionIndex
{
  FirstAction = 0,
  SecondAction,
  ThirdAction
};

QTAIMExtension::QTAIMExtension(QObject* aParent)
  : QtGui::ExtensionPlugin(aParent)
{
  // create an action for our first action
  QAction* action = new QAction(this);
  action->setText(tr("Molecular Graph..."));
  m_actions.append(action);
  action->setData(FirstAction);
  connect(action, SIGNAL(triggered()), SLOT(triggered()));

  // create an action for our second action
  action = new QAction(this);
  action->setText(tr("Molecular Graph with Lone Pairs..."));
  m_actions.append(action);
  action->setData(SecondAction);
  connect(action, SIGNAL(triggered()), SLOT(triggered()));

  // create an action for our third action
  action = new QAction(this);
  action->setText(tr("Atomic Charge..."));
  m_actions.append(action);
  action->setData(ThirdAction);
  connect(action, SIGNAL(triggered()), SLOT(triggered()));
}

QTAIMExtension::~QTAIMExtension()
{
}

QList<QAction*> QTAIMExtension::actions() const
{
  return m_actions;
}

QStringList QTAIMExtension::menuPath(QAction*) const
{
  return QStringList() << tr("&Analysis") << tr("QTAIM");
}

void QTAIMExtension::setMolecule(QtGui::Molecule* molecule)
{
  m_molecule = molecule;
}

void QTAIMExtension::triggered()
{
  QAction* action = qobject_cast<QAction*>(sender());
  if (!action)
    return;

  bool wavefunctionAlreadyLoaded;

  if (m_molecule->property("QTAIMComment").isValid()) {
    wavefunctionAlreadyLoaded = true;
  } else {
    wavefunctionAlreadyLoaded = false;
  }

  int i = action->data().toInt();

  QTime timer;
  timer.start();

  QString fileName;
  if (wavefunctionAlreadyLoaded) {
    // do nothing
  } else {
    fileName = QFileDialog::getOpenFileName(
      new QWidget, tr("Open WFN File"), QDir::homePath(),
      tr("WFN files (*.wfn);;All files (*.*)"));

    if (fileName.isNull()) {
      qDebug() << "No such file.";
      return;
    }
  }

  // Instantiate a Wavefunction
  bool success;
  QTAIMWavefunction wfn;
  if (wavefunctionAlreadyLoaded) {
    success = wfn.initializeWithMoleculeProperties(m_molecule);
  } else {
    success = wfn.initializeWithWFNFile(fileName);
  }

  if (!success) {
    if (wavefunctionAlreadyLoaded) {
      qDebug() << "Error initializing wavefunction.";
    } else {
      qDebug() << "Error reading WFN file.";
    }
    return;
  }

  QtGui::Molecule::MoleculeChanges changes;
  if (m_molecule->atomCount() > 0)
    changes |= QtGui::Molecule::Atoms | QtGui::Molecule::Removed;
  if (m_molecule->bondCount() > 0)
    changes |= QtGui::Molecule::Bonds | QtGui::Molecule::Removed;

  m_molecule->clearAtoms();
  m_molecule->emitChanged(static_cast<unsigned int>(changes));

  // Instantiate an Evaluator
  QTAIMWavefunctionEvaluator eval(wfn);

  switch (i) {
    case FirstAction: // Molecular Graph
    {
      // Instantiate a Critical Point Locator
      QTAIMCriticalPointLocator cpl(wfn);

      // Locate the Nuclear Critical Points
      cpl.locateNuclearCriticalPoints();

      // QLists of results
      QList<qint64> nucChargeList = wfn.nuclearChargesList();
      QList<QVector3D> ncpList = cpl.nuclearCriticalPoints();

      QVariantList xNCPsVariantList;
      QVariantList yNCPsVariantList;
      QVariantList zNCPsVariantList;
      QVariantList nuclearChargesVariantList;

      const qreal convertBohrToAngstrom = 0.529177249;

      // Nuclear Critical Points
      for (qint64 n = 0; n < ncpList.length(); ++n) {
        QVector3D thisNuclearCriticalPoint = ncpList.at(n);

        qreal x = thisNuclearCriticalPoint.x() * convertBohrToAngstrom;
        qreal y = thisNuclearCriticalPoint.y() * convertBohrToAngstrom;
        qreal z = thisNuclearCriticalPoint.z() * convertBohrToAngstrom;

        xNCPsVariantList.append(x);
        yNCPsVariantList.append(y);
        zNCPsVariantList.append(z);
        nuclearChargesVariantList.append(wfn.nuclearCharge(n));
      }

      m_molecule->setProperty("QTAIMXNuclearCriticalPoints", xNCPsVariantList);
      m_molecule->setProperty("QTAIMYNuclearCriticalPoints", yNCPsVariantList);
      m_molecule->setProperty("QTAIMZNuclearCriticalPoints", zNCPsVariantList);
      m_molecule->setProperty("QTAIMNuclearCharges", nuclearChargesVariantList);

      // Nuclei stored as Atoms
      for (qint64 n = 0; n < wfn.numberOfNuclei(); ++n) {
        qreal x = wfn.xNuclearCoordinate(n) * convertBohrToAngstrom;
        qreal y = wfn.yNuclearCoordinate(n) * convertBohrToAngstrom;
        qreal z = wfn.zNuclearCoordinate(n) * convertBohrToAngstrom;

        int Z = (int)wfn.nuclearCharge(n);

        m_molecule->addAtom(static_cast<unsigned char>(Z))
          .setPosition3d(Vector3(static_cast<Real>(x), static_cast<Real>(y),
                                 static_cast<Real>(z)));
      }

      if (m_molecule->atomCount() > 0) {
        m_molecule->emitChanged(QtGui::Molecule::Atoms |
                                QtGui::Molecule::Added);
      }

      // Locate the Bond Critical Points and Trace Bond Paths
      cpl.locateBondCriticalPoints();

      // BCP and Bond Path Results
      QList<QVector3D> bcpList = cpl.bondCriticalPoints();
      QList<QList<QVector3D>> bondPathList = cpl.bondPaths();
      QList<QPair<qint64, qint64>> bondedAtomsList = cpl.bondedAtoms();
      QList<qreal> laplacianAtBondCriticalPoints =
        cpl.laplacianAtBondCriticalPoints();
      QList<qreal> ellipticityAtBondCriticalPoints =
        cpl.ellipticityAtBondCriticalPoints();

      QVariantList xBCPsVariantList;
      QVariantList yBCPsVariantList;
      QVariantList zBCPsVariantList;
      QVariantList firstNCPIndexVariantList;
      QVariantList secondNCPIndexVariantList;
      QVariantList laplacianAtBondCriticalPointsVariantList;
      QVariantList ellipticityAtBondCriticalPointsVariantList;

      QVariantList bondPathSegmentStartIndexVariantList;
      QVariantList bondPathSegmentEndIndexVariantList;
      QVariantList xBondPathsVariantList;
      QVariantList yBondPathsVariantList;
      QVariantList zBondPathsVariantList;

      // Connectivity stored as Bonds

      qint64 bpCtr = 0;
      qint64 numAtoms = static_cast<qint64>(m_molecule->atomCount());

      for (qint64 atom0 = 0; atom0 < numAtoms - 1; ++atom0) {
        for (qint64 atom1 = atom0 + 1; atom1 < numAtoms; ++atom1) {

          bool areBonded = false;

          for (qint64 bondPair = 0; bondPair < bondedAtomsList.length();
               ++bondPair) {
            if (atom0 == bondedAtomsList.at(bondPair).first &&
                atom1 == bondedAtomsList.at(bondPair).second) {
              areBonded = true;

              if (areBonded) {

                if ((wfn.nuclearCharge(atom0) == 1 ||
                     wfn.nuclearCharge(atom1) == 1) &&
                    laplacianAtBondCriticalPoints.at(bondPair) > 0.0) {
                  // do not draw Bond because it looks like hydrogen bond
                } else {
                  m_molecule->addBond(
                    m_molecule->atom(static_cast<Index>(atom0)),
                    m_molecule->atom(static_cast<Index>(atom1)));
                  //            bond->setAromaticity(isAromatic);
                  //            bond->setOrder( (int) order);
                }

                qreal x = bcpList.at(bondPair).x() * convertBohrToAngstrom;
                qreal y = bcpList.at(bondPair).y() * convertBohrToAngstrom;
                qreal z = bcpList.at(bondPair).z() * convertBohrToAngstrom;

                xBCPsVariantList.append(x);
                yBCPsVariantList.append(y);
                zBCPsVariantList.append(z);

                firstNCPIndexVariantList.append(atom0);
                secondNCPIndexVariantList.append(atom1);

                laplacianAtBondCriticalPointsVariantList.append(
                  laplacianAtBondCriticalPoints.at(bondPair));
                ellipticityAtBondCriticalPointsVariantList.append(
                  ellipticityAtBondCriticalPoints.at(bondPair));

                bondPathSegmentStartIndexVariantList.append(bpCtr);
                for (qint64 j = 0; j < bondPathList.at(bondPair).length();
                     ++j) {
                  x =
                    bondPathList.at(bondPair).at(j).x() * convertBohrToAngstrom;
                  y =
                    bondPathList.at(bondPair).at(j).y() * convertBohrToAngstrom;
                  z =
                    bondPathList.at(bondPair).at(j).z() * convertBohrToAngstrom;

                  xBondPathsVariantList.append(x);
                  yBondPathsVariantList.append(y);
                  zBondPathsVariantList.append(z);

                  bpCtr++;
                }
                bondPathSegmentEndIndexVariantList.append(bpCtr);
              }
            }
          } // bond pairs
        }   // atom1
      }     // atom 0

      m_molecule->setProperty("QTAIMXBondCriticalPoints", xBCPsVariantList);
      m_molecule->setProperty("QTAIMYBondCriticalPoints", yBCPsVariantList);
      m_molecule->setProperty("QTAIMZBondCriticalPoints", zBCPsVariantList);
      m_molecule->setProperty("QTAIMFirstNCPIndexVariantList",
                              firstNCPIndexVariantList);
      m_molecule->setProperty("QTAIMSecondNCPIndexVariantList",
                              secondNCPIndexVariantList);
      m_molecule->setProperty("QTAIMLaplacianAtBondCriticalPoints",
                              laplacianAtBondCriticalPointsVariantList);
      m_molecule->setProperty("QTAIMEllipticityAtBondCriticalPoints",
                              ellipticityAtBondCriticalPointsVariantList);

      m_molecule->setProperty("QTAIMBondPathSegmentStartIndex",
                              bondPathSegmentStartIndexVariantList);
      m_molecule->setProperty("QTAIMBondPathSegmentEndIndex",
                              bondPathSegmentEndIndexVariantList);
      m_molecule->setProperty("QTAIMXBondPaths", xBondPathsVariantList);
      m_molecule->setProperty("QTAIMYBondPaths", yBondPathsVariantList);
      m_molecule->setProperty("QTAIMZBondPaths", zBondPathsVariantList);

      if (m_molecule->bondCount()) {
        m_molecule->emitChanged(QtGui::Molecule::Bonds |
                                QtGui::Molecule::Added);
      }
    } break;
    case SecondAction: // Molecular Graph with Lone Pairs
    {
      // Instantiate a Critical Point Locator
      QTAIMCriticalPointLocator cpl(wfn);

      // Locate the Nuclear Critical Points
      cpl.locateNuclearCriticalPoints();

      // QLists of results
      QList<qint64> nucChargeList = wfn.nuclearChargesList();
      QList<QVector3D> ncpList = cpl.nuclearCriticalPoints();

      QVariantList xNCPsVariantList;
      QVariantList yNCPsVariantList;
      QVariantList zNCPsVariantList;
      QVariantList nuclearChargesVariantList;

      const qreal convertBohrToAngstrom = 0.529177249;

      // Nuclear Critical Points
      for (qint64 n = 0; n < ncpList.length(); ++n) {
        QVector3D thisNuclearCriticalPoint = ncpList.at(n);

        qreal x = thisNuclearCriticalPoint.x() * convertBohrToAngstrom;
        qreal y = thisNuclearCriticalPoint.y() * convertBohrToAngstrom;
        qreal z = thisNuclearCriticalPoint.z() * convertBohrToAngstrom;

        xNCPsVariantList.append(x);
        yNCPsVariantList.append(y);
        zNCPsVariantList.append(z);
        nuclearChargesVariantList.append(wfn.nuclearCharge(n));
      }

      m_molecule->setProperty("QTAIMXNuclearCriticalPoints", xNCPsVariantList);
      m_molecule->setProperty("QTAIMYNuclearCriticalPoints", yNCPsVariantList);
      m_molecule->setProperty("QTAIMZNuclearCriticalPoints", zNCPsVariantList);
      m_molecule->setProperty("QTAIMNuclearCharges", nuclearChargesVariantList);

      // Nuclei stored as Atoms
      for (qint64 n = 0; n < wfn.numberOfNuclei(); ++n) {
        qreal x = wfn.xNuclearCoordinate(n) * convertBohrToAngstrom;
        qreal y = wfn.yNuclearCoordinate(n) * convertBohrToAngstrom;
        qreal z = wfn.zNuclearCoordinate(n) * convertBohrToAngstrom;

        int Z = (int)wfn.nuclearCharge(n);

        m_molecule->addAtom(static_cast<unsigned char>(Z))
          .setPosition3d(Vector3(static_cast<Real>(x), static_cast<Real>(y),
                                 static_cast<Real>(z)));
      }

      if (m_molecule->atomCount() > 0) {
        m_molecule->emitChanged(QtGui::Molecule::Atoms |
                                QtGui::Molecule::Added);
      }

      // Locate the Bond Critical Points and Trace Bond Paths
      cpl.locateBondCriticalPoints();

      // BCP and Bond Path Results
      QList<QVector3D> bcpList = cpl.bondCriticalPoints();
      QList<QList<QVector3D>> bondPathList = cpl.bondPaths();
      QList<QPair<qint64, qint64>> bondedAtomsList = cpl.bondedAtoms();
      QList<qreal> laplacianAtBondCriticalPoints =
        cpl.laplacianAtBondCriticalPoints();
      QList<qreal> ellipticityAtBondCriticalPoints =
        cpl.ellipticityAtBondCriticalPoints();

      QVariantList xBCPsVariantList;
      QVariantList yBCPsVariantList;
      QVariantList zBCPsVariantList;
      QVariantList firstNCPIndexVariantList;
      QVariantList secondNCPIndexVariantList;
      QVariantList laplacianAtBondCriticalPointsVariantList;
      QVariantList ellipticityAtBondCriticalPointsVariantList;

      QVariantList bondPathSegmentStartIndexVariantList;
      QVariantList bondPathSegmentEndIndexVariantList;
      QVariantList xBondPathsVariantList;
      QVariantList yBondPathsVariantList;
      QVariantList zBondPathsVariantList;

      // Connectivity stored as Bonds

      qint64 bpCtr = 0;
      qint64 numAtoms = static_cast<qint64>(m_molecule->atomCount());

      for (qint64 atom0 = 0; atom0 < numAtoms - 1; ++atom0) {
        for (qint64 atom1 = atom0 + 1; atom1 < numAtoms; ++atom1) {

          bool areBonded = false;

          for (qint64 bondPair = 0; bondPair < bondedAtomsList.length();
               ++bondPair) {
            if (atom0 == bondedAtomsList.at(bondPair).first &&
                atom1 == bondedAtomsList.at(bondPair).second) {
              areBonded = true;

              if (areBonded) {

                if ((wfn.nuclearCharge(atom0) == 1 ||
                     wfn.nuclearCharge(atom1) == 1) &&
                    laplacianAtBondCriticalPoints.at(bondPair) > 0.0) {
                  // do not draw Bond because it looks like hydrogen bond
                } else {
                  m_molecule->addBond(
                    m_molecule->atom(static_cast<Index>(atom0)),
                    m_molecule->atom(static_cast<Index>(atom1)));
                  //            bond->setAromaticity(isAromatic);
                  //            bond->setOrder( (int) order);
                }

                qreal x = bcpList.at(bondPair).x() * convertBohrToAngstrom;
                qreal y = bcpList.at(bondPair).y() * convertBohrToAngstrom;
                qreal z = bcpList.at(bondPair).z() * convertBohrToAngstrom;

                xBCPsVariantList.append(x);
                yBCPsVariantList.append(y);
                zBCPsVariantList.append(z);

                firstNCPIndexVariantList.append(atom0);
                secondNCPIndexVariantList.append(atom1);

                laplacianAtBondCriticalPointsVariantList.append(
                  laplacianAtBondCriticalPoints.at(bondPair));
                ellipticityAtBondCriticalPointsVariantList.append(
                  ellipticityAtBondCriticalPoints.at(bondPair));

                bondPathSegmentStartIndexVariantList.append(bpCtr);
                for (qint64 j = 0; j < bondPathList.at(bondPair).length();
                     ++j) {
                  x =
                    bondPathList.at(bondPair).at(j).x() * convertBohrToAngstrom;
                  y =
                    bondPathList.at(bondPair).at(j).y() * convertBohrToAngstrom;
                  z =
                    bondPathList.at(bondPair).at(j).z() * convertBohrToAngstrom;

                  xBondPathsVariantList.append(x);
                  yBondPathsVariantList.append(y);
                  zBondPathsVariantList.append(z);

                  bpCtr++;
                }
                bondPathSegmentEndIndexVariantList.append(bpCtr);
              }
            }
          } // bond pairs
        }   // atom1
      }     // atom 0

      m_molecule->setProperty("QTAIMXBondCriticalPoints", xBCPsVariantList);
      m_molecule->setProperty("QTAIMYBondCriticalPoints", yBCPsVariantList);
      m_molecule->setProperty("QTAIMZBondCriticalPoints", zBCPsVariantList);
      m_molecule->setProperty("QTAIMFirstNCPIndexVariantList",
                              firstNCPIndexVariantList);
      m_molecule->setProperty("QTAIMSecondNCPIndexVariantList",
                              secondNCPIndexVariantList);
      m_molecule->setProperty("QTAIMLaplacianAtBondCriticalPoints",
                              laplacianAtBondCriticalPointsVariantList);
      m_molecule->setProperty("QTAIMEllipticityAtBondCriticalPoints",
                              ellipticityAtBondCriticalPointsVariantList);

      m_molecule->setProperty("QTAIMBondPathSegmentStartIndex",
                              bondPathSegmentStartIndexVariantList);
      m_molecule->setProperty("QTAIMBondPathSegmentEndIndex",
                              bondPathSegmentEndIndexVariantList);
      m_molecule->setProperty("QTAIMXBondPaths", xBondPathsVariantList);
      m_molecule->setProperty("QTAIMYBondPaths", yBondPathsVariantList);
      m_molecule->setProperty("QTAIMZBondPaths", zBondPathsVariantList);

      if (m_molecule->bondCount()) {
        m_molecule->emitChanged(QtGui::Molecule::Bonds |
                                QtGui::Molecule::Added);
      }

      // Locate Electron Density Sources / Lone Pairs

      cpl.locateElectronDensitySources();
      QList<QVector3D> electronDensitySourcesList =
        cpl.electronDensitySources();

      QVariantList xElectronDensitySourcesVariantList;
      QVariantList yElectronDensitySourcesVariantList;
      QVariantList zElectronDensitySourcesVariantList;

      for (qint64 n = 0; n < electronDensitySourcesList.length(); ++n) {
        QVector3D thisCriticalPoint = electronDensitySourcesList.at(n);

        qreal x = thisCriticalPoint.x() * convertBohrToAngstrom;
        qreal y = thisCriticalPoint.y() * convertBohrToAngstrom;
        qreal z = thisCriticalPoint.z() * convertBohrToAngstrom;

        xElectronDensitySourcesVariantList.append(x);
        yElectronDensitySourcesVariantList.append(y);
        zElectronDensitySourcesVariantList.append(z);
      }

      m_molecule->setProperty("QTAIMXElectronDensitySources",
                              xElectronDensitySourcesVariantList);
      m_molecule->setProperty("QTAIMYElectronDensitySources",
                              yElectronDensitySourcesVariantList);
      m_molecule->setProperty("QTAIMZElectronDensitySources",
                              zElectronDensitySourcesVariantList);

      // TODO need some way to indicate that the properties have changed:
      //        m_molecule->update();

    } break;
    case ThirdAction:
      // perform third action
      {
        // Instantiate a Critical Point Locator
        QTAIMCriticalPointLocator cpl(wfn);

        // Locate the Nuclear Critical Points
        cpl.locateNuclearCriticalPoints();

        // QLists of results
        QList<qint64> nucChargeList = wfn.nuclearChargesList();
        QList<QVector3D> ncpList = cpl.nuclearCriticalPoints();

        QVariantList xNCPsVariantList;
        QVariantList yNCPsVariantList;
        QVariantList zNCPsVariantList;
        QVariantList nuclearChargesVariantList;

        const qreal convertBohrToAngstrom = 0.529177249;

        // Nuclear Critical Points
        for (qint64 n = 0; n < ncpList.length(); ++n) {
          QVector3D thisNuclearCriticalPoint = ncpList.at(n);

          qreal x = thisNuclearCriticalPoint.x() * convertBohrToAngstrom;
          qreal y = thisNuclearCriticalPoint.y() * convertBohrToAngstrom;
          qreal z = thisNuclearCriticalPoint.z() * convertBohrToAngstrom;

          xNCPsVariantList.append(x);
          yNCPsVariantList.append(y);
          zNCPsVariantList.append(z);
          nuclearChargesVariantList.append(wfn.nuclearCharge(n));
        }

        m_molecule->setProperty("QTAIMXNuclearCriticalPoints",
                                xNCPsVariantList);
        m_molecule->setProperty("QTAIMYNuclearCriticalPoints",
                                yNCPsVariantList);
        m_molecule->setProperty("QTAIMZNuclearCriticalPoints",
                                zNCPsVariantList);
        m_molecule->setProperty("QTAIMNuclearCharges",
                                nuclearChargesVariantList);

        // Nuclei stored as Atoms
        for (qint64 n = 0; n < wfn.numberOfNuclei(); ++n) {
          qreal x = wfn.xNuclearCoordinate(n) * convertBohrToAngstrom;
          qreal y = wfn.yNuclearCoordinate(n) * convertBohrToAngstrom;
          qreal z = wfn.zNuclearCoordinate(n) * convertBohrToAngstrom;

          int Z = (int)wfn.nuclearCharge(n);

          m_molecule->addAtom(static_cast<unsigned char>(Z))
            .setPosition3d(Vector3(static_cast<Real>(x), static_cast<Real>(y),
                                   static_cast<Real>(z)));
        }

        if (m_molecule->atomCount() > 0) {
          m_molecule->emitChanged(QtGui::Molecule::Atoms |
                                  QtGui::Molecule::Added);
        }

        // Locate the Bond Critical Points and Trace Bond Paths
        cpl.locateBondCriticalPoints();

        // BCP and Bond Path Results
        QList<QVector3D> bcpList = cpl.bondCriticalPoints();
        QList<QList<QVector3D>> bondPathList = cpl.bondPaths();
        QList<QPair<qint64, qint64>> bondedAtomsList = cpl.bondedAtoms();
        QList<qreal> laplacianAtBondCriticalPoints =
          cpl.laplacianAtBondCriticalPoints();
        QList<qreal> ellipticityAtBondCriticalPoints =
          cpl.ellipticityAtBondCriticalPoints();

        QVariantList xBCPsVariantList;
        QVariantList yBCPsVariantList;
        QVariantList zBCPsVariantList;
        QVariantList firstNCPIndexVariantList;
        QVariantList secondNCPIndexVariantList;
        QVariantList laplacianAtBondCriticalPointsVariantList;
        QVariantList ellipticityAtBondCriticalPointsVariantList;

        QVariantList bondPathSegmentStartIndexVariantList;
        QVariantList bondPathSegmentEndIndexVariantList;
        QVariantList xBondPathsVariantList;
        QVariantList yBondPathsVariantList;
        QVariantList zBondPathsVariantList;

        // Connectivity stored as Bonds

        qint64 bpCtr = 0;
        qint64 numAtoms = static_cast<qint64>(m_molecule->atomCount());

        for (qint64 atom0 = 0; atom0 < numAtoms - 1; ++atom0) {
          for (qint64 atom1 = atom0 + 1; atom1 < numAtoms; ++atom1) {

            bool areBonded = false;

            for (qint64 bondPair = 0; bondPair < bondedAtomsList.length();
                 ++bondPair) {
              if (atom0 == bondedAtomsList.at(bondPair).first &&
                  atom1 == bondedAtomsList.at(bondPair).second) {
                areBonded = true;

                if (areBonded) {

                  if ((wfn.nuclearCharge(atom0) == 1 ||
                       wfn.nuclearCharge(atom1) == 1) &&
                      laplacianAtBondCriticalPoints.at(bondPair) > 0.0) {
                    // do not draw Bond because it looks like hydrogen bond
                  } else {
                    m_molecule->addBond(
                      m_molecule->atom(static_cast<Index>(atom0)),
                      m_molecule->atom(static_cast<Index>(atom1)));
                    //            bond->setAromaticity(isAromatic);
                    //            bond->setOrder( (int) order);
                  }

                  qreal x = bcpList.at(bondPair).x() * convertBohrToAngstrom;
                  qreal y = bcpList.at(bondPair).y() * convertBohrToAngstrom;
                  qreal z = bcpList.at(bondPair).z() * convertBohrToAngstrom;

                  xBCPsVariantList.append(x);
                  yBCPsVariantList.append(y);
                  zBCPsVariantList.append(z);

                  firstNCPIndexVariantList.append(atom0);
                  secondNCPIndexVariantList.append(atom1);

                  laplacianAtBondCriticalPointsVariantList.append(
                    laplacianAtBondCriticalPoints.at(bondPair));
                  ellipticityAtBondCriticalPointsVariantList.append(
                    ellipticityAtBondCriticalPoints.at(bondPair));

                  bondPathSegmentStartIndexVariantList.append(bpCtr);
                  for (qint64 j = 0; j < bondPathList.at(bondPair).length();
                       ++j) {
                    x = bondPathList.at(bondPair).at(j).x() *
                        convertBohrToAngstrom;
                    y = bondPathList.at(bondPair).at(j).y() *
                        convertBohrToAngstrom;
                    z = bondPathList.at(bondPair).at(j).z() *
                        convertBohrToAngstrom;

                    xBondPathsVariantList.append(x);
                    yBondPathsVariantList.append(y);
                    zBondPathsVariantList.append(z);

                    bpCtr++;
                  }
                  bondPathSegmentEndIndexVariantList.append(bpCtr);
                }
              }
            } // bond pairs
          }   // atom1
        }     // atom 0

        m_molecule->setProperty("QTAIMXBondCriticalPoints", xBCPsVariantList);
        m_molecule->setProperty("QTAIMYBondCriticalPoints", yBCPsVariantList);
        m_molecule->setProperty("QTAIMZBondCriticalPoints", zBCPsVariantList);
        m_molecule->setProperty("QTAIMFirstNCPIndexVariantList",
                                firstNCPIndexVariantList);
        m_molecule->setProperty("QTAIMSecondNCPIndexVariantList",
                                secondNCPIndexVariantList);
        m_molecule->setProperty("QTAIMLaplacianAtBondCriticalPoints",
                                laplacianAtBondCriticalPointsVariantList);
        m_molecule->setProperty("QTAIMEllipticityAtBondCriticalPoints",
                                ellipticityAtBondCriticalPointsVariantList);

        m_molecule->setProperty("QTAIMBondPathSegmentStartIndex",
                                bondPathSegmentStartIndexVariantList);
        m_molecule->setProperty("QTAIMBondPathSegmentEndIndex",
                                bondPathSegmentEndIndexVariantList);
        m_molecule->setProperty("QTAIMXBondPaths", xBondPathsVariantList);
        m_molecule->setProperty("QTAIMYBondPaths", yBondPathsVariantList);
        m_molecule->setProperty("QTAIMZBondPaths", zBondPathsVariantList);

        if (m_molecule->bondCount() > 0) {
          m_molecule->emitChanged(QtGui::Molecule::Bonds |
                                  QtGui::Molecule::Added);
        }

        // Electron Density
        qint64 mode = 0;

        // All Atomic Basins
        QList<qint64> basins;
        for (qint64 j = 0; j < wfn.numberOfNuclei(); ++j) {
          basins.append(j);
        }

        QTAIMCubature cub(wfn);

        //        QTime time;
        //        time.start();
        QList<QPair<qreal, qreal>> results = cub.integrate(mode, basins);
        //        qDebug() << "Time Elapsed:" << time.elapsed();

        for (qint64 j = 0; j < results.length(); ++j) {
          qDebug() << "basin" << j << results.at(j).first
                   << results.at(j).second;
        }

        // TODO: Set the properties of the atoms.
        // I don't know why this bombs.
        for (qint64 j = 0; static_cast<qint64>(m_molecule->atomCount()); ++j) {
          //          Atom *atom=m_molecule->atoms().at(i);
          //          const qreal charge=results.at(i).first;
          //          atom->setPartialCharge( charge  );
        }
      }
      break;
  }

  emit requestActiveTool("Navigator");
  emit requestActiveDisplayTypes(QStringList() << "QTAIMScenePlugin");

  return;
}

} // end namespace QtPlugins
} // end namespace Avogadro
