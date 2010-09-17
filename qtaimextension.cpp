
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

#include "qtaimextension.h"

#include <avogadro/molecule.h>
#include <avogadro/atom.h>
#include <avogadro/bond.h>
#include <avogadro/painter.h>

#include <avogadro/qtaimnuclearcriticalpoint.h>
#include <avogadro/qtaimbondcriticalpoint.h>

#include <QAction>

#include <QString>
#include <QDebug>
#include <QList>
#include <QVector3D>
#include <QPair>
#include <QFileDialog>
#include <QDir>

#include <QThread>

#include "qtaimwavefunction.h"
#include "qtaimwavefunctionevaluator.h"
#include "qtaimcriticalpointlocator.h"

#include <QTime>

#include <Eigen/Eigen>

using namespace std;
using namespace Eigen;

namespace Avogadro
{

  enum QTAIMExtensionIndex {
    FirstAction = 0,
    SecondAction
  };

  QTAIMExtension::QTAIMExtension( QObject *parent ) : Extension( parent )
  {
    // create an action for our first action
    QAction *action = new QAction( this );
    action->setText( tr("Molecular Graph" ));
    m_actions.append( action );
    action->setData( FirstAction );

    // create an action for our second action
    action = new QAction( this );
    action->setText( tr("Atomic Charge" ));
    m_actions.append( action );
    action->setData( SecondAction );

  }

  QTAIMExtension::~QTAIMExtension()
  {
  }

  QList<QAction *> QTAIMExtension::actions() const
  {
    return m_actions;
  }

  QString QTAIMExtension::menuPath(QAction *action) const
  {
    int i = action->data().toInt();

    switch ( i ) {
    case FirstAction:
      return tr("E&xtensions") + '>' + tr("QTAIM");
      break;
    case SecondAction:
      return tr("E&xtensions") + '>' + tr("QTAIM");
      break;
    }
    return "";
  }

  QDockWidget * QTAIMExtension::dockWidget()
  {
    return 0;
  }

  void QTAIMExtension::setMolecule(Molecule *molecule)
  {
    m_molecule = molecule;
  }

  QUndoCommand* QTAIMExtension::performAction(QAction *action, GLWidget *widget)
  {

    int i = action->data().toInt();

    QTime timer;
    timer.start();

    switch ( i ) {
    case FirstAction: // Molecular Graph
    {
      QString fileName = QFileDialog::getOpenFileName(
          new QWidget,
          tr("Open WFN File"),
          QDir::homePath(),
          tr("WFN files (*.wfn);;All files (*.*)") );

      if(fileName.isNull())
      {
        qDebug() << "No such file.";
        return 0;
      }

      // Instantiate a Wavefunction

      QTAIMWavefunction wfn;
      bool success=wfn.initializeWithWFNFile(fileName);

      if(!success)
      {
        qDebug() << "Error reading WFN file.";
        return 0;
      }

      m_molecule->clear();

      // Instantiate an Evaluator
      QTAIMWavefunctionEvaluator eval(wfn);

      // Instantiate a Critical Point Locator
      QTAIMCriticalPointLocator cpl(wfn);

      // Locate the Nuclear Critical Points
      cpl.locateNuclearCriticalPoints();

      // QLists of results
      QList<qint64>    nucChargeList=wfn.nuclearChargesList();
      QList<QVector3D> ncpList=cpl.nuclearCriticalPoints();

      const qreal convertBohrToAngstroem=0.529177249;

      // Nuclear Critical Points
      for( qint64 ncp=0 ; ncp < ncpList.length() ; ++ncp )
      {
        QVector3D thisNuclearCriticalPoint=ncpList.at(ncp);

        qreal x=thisNuclearCriticalPoint.x() * convertBohrToAngstroem;
        qreal y=thisNuclearCriticalPoint.y() * convertBohrToAngstroem;
        qreal z=thisNuclearCriticalPoint.z() * convertBohrToAngstroem;

        int Z=(int) wfn.nuclearCharge(ncp);

        QTAIMNuclearCriticalPoint *ncp=m_molecule->addNuclearCriticalPoint();
        ncp->setPos( Eigen::Vector3d(x,y,z) );
        ncp->setAtomicNumber(Z);
      }

      // Nuclei stored as Atoms
      for( qint64 n=0 ; n < wfn.numberOfNuclei() ; ++n )
      {
        qreal x=wfn.xNuclearCoordinate(n) * convertBohrToAngstroem;
        qreal y=wfn.yNuclearCoordinate(n) * convertBohrToAngstroem;
        qreal z=wfn.zNuclearCoordinate(n) * convertBohrToAngstroem;

        int Z=(int) wfn.nuclearCharge(n);

        Atom *atom=m_molecule->addAtom();
        atom->setPos( Eigen::Vector3d(x,y,z) );
        atom->setAtomicNumber(Z);
      }

      m_molecule->update();

      // Locate the Bond Critical Points and Trace Bond Paths
      cpl.locateBondCriticalPoints();

      QList<QVector3D> bcpList=cpl.bondCriticalPoints();

      QList<QList<QVector3D> > bondPathList=cpl.bondPaths();
      QList<QPair<qint64,qint64> > bondedAtomsList=cpl.bondedAtoms();

      QList<qreal> laplacianAtBondCriticalPoints=cpl.laplacianAtBondCriticalPoints();
      QList<qreal> ellipticityAtBondCriticalPoints=cpl.ellipticityAtBondCriticalPoints();

      QList<Atom *> currentAtoms=m_molecule->atoms();
      QList<QTAIMNuclearCriticalPoint *> currentNuclearCriticalPoints=m_molecule->nuclearCriticalPoints();

      // Connectivity stored as Bonds

      for( qint64 atom0=0 ; atom0 < currentAtoms.length() - 1 ; ++atom0 )
      {
        for( qint64 atom1=atom0+1 ; atom1 < currentAtoms.length() ; ++atom1 )
        {
          bool areBonded=false;
          bool isAromatic=false;
          qint64 order=1;

          for( qint64 bondPair=0 ; bondPair < bondedAtomsList.length() ; ++bondPair )
          {
            if( atom0 == bondedAtomsList.at(bondPair).first && atom1 == bondedAtomsList.at(bondPair).second  )
            {
              areBonded=true;

              if( areBonded )
              {

                if( (wfn.nuclearCharge(atom0) == 1 || wfn.nuclearCharge(atom1) == 1) &&
                    laplacianAtBondCriticalPoints.at(bondPair) > 0.0
                    )
                {
                  // do not draw Bond because it looks like hydrogen bond
                }
                else
                {
                  Bond *bond=m_molecule->addBond();
                  bond->setBegin( currentAtoms.at(atom0) );
                  bond->setEnd( currentAtoms.at(atom1) );
                  //            bond->setAromaticity(isAromatic);
                  //            bond->setOrder( (int) order);
                }

                QTAIMBondCriticalPoint *bcp=m_molecule->addBondCriticalPoint();
                bcp->setBegin( currentNuclearCriticalPoints.at(atom0) );
                bcp->setEnd( currentNuclearCriticalPoints.at(atom1) );

                qreal x=bcpList.at(bondPair).x() * convertBohrToAngstroem;
                qreal y=bcpList.at(bondPair).y() * convertBohrToAngstroem;
                qreal z=bcpList.at(bondPair).z() * convertBohrToAngstroem;

                bcp->setPos( Eigen::Vector3d(x,y,z)  );

                QList<Eigen::Vector3d> bondPath;
                for( qint64 i=0; i < bondPathList.at(bondPair).length() ; ++i )
                {
                  qreal x=bondPathList.at(bondPair).at(i).x() * convertBohrToAngstroem;
                  qreal y=bondPathList.at(bondPair).at(i).y() * convertBohrToAngstroem;
                  qreal z=bondPathList.at(bondPair).at(i).z() * convertBohrToAngstroem;

                  bondPath.append( Eigen::Vector3d(x,y,z) );
                }
                bcp->setBondPath(bondPath);
                bcp->setLaplacian( laplacianAtBondCriticalPoints.at(bondPair) );
                bcp->setEllipticity( ellipticityAtBondCriticalPoints.at(bondPair) );

              }

            }
          } // bond pairs
        } // atom1
      } // atom 0

      m_molecule->update();
      }
      break;
      case SecondAction:
      // perform second action
      qDebug() << "Not Implemented: Come back tomorrow.";
      break;
    }

    return 0;
  }

}

Q_EXPORT_PLUGIN2(qtaimextension, Avogadro::QTAIMExtensionFactory)

