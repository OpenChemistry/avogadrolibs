
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
#include "qtaimcubature.h"

#include <QTime>

using namespace std;
using namespace Eigen;

namespace Avogadro
{

  enum QTAIMExtensionIndex {
    FirstAction = 0,
    SecondAction,
    ThirdAction
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
    action->setText( tr("Molecular Graph with Lone Pairs" ));
    m_actions.append( action );
    action->setData( SecondAction );

    // create an action for our third action
    action = new QAction( this );
    action->setText( tr("Atomic Charge" ));
    m_actions.append( action );
    action->setData( ThirdAction );
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
    case ThirdAction:
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

  QUndoCommand* QTAIMExtension::performAction(QAction *action, GLWidget *)
  {

    bool wavefunctionAlreadyLoaded;

    if( m_molecule->property("QTAIMComment").isValid() )
    {
      wavefunctionAlreadyLoaded=true;
    }
    else
    {
      wavefunctionAlreadyLoaded=false;
    }

    int i = action->data().toInt();

    QTime timer;
    timer.start();

    QString fileName;
    if( wavefunctionAlreadyLoaded )
    {
      // do nothing
    }
    else
    {
       fileName = QFileDialog::getOpenFileName(
          new QWidget,
          tr("Open WFN File"),
          QDir::homePath(),
          tr("WFN files (*.wfn);;All files (*.*)") );

      if(fileName.isNull())
      {
        qDebug() << "No such file.";
        return 0;
      }
    }

    // Instantiate a Wavefunction
    bool success;
    QTAIMWavefunction wfn;
    if( wavefunctionAlreadyLoaded )
    {
      success=wfn.initializeWithMoleculeProperties(m_molecule);
    }
    else
    {
      success=wfn.initializeWithWFNFile(fileName);
    }

    if(!success)
    {
      if( wavefunctionAlreadyLoaded )
      {
        qDebug() << "Error initializing wavefunction.";
      }
      else
      {
        qDebug() << "Error reading WFN file.";
      }
        return 0;
    }

    m_molecule->clear();

    // Instantiate an Evaluator
    QTAIMWavefunctionEvaluator eval(wfn);

    switch ( i ) {
    case FirstAction: // Molecular Graph
      {
        // Instantiate a Critical Point Locator
        QTAIMCriticalPointLocator cpl(wfn);

        // Locate the Nuclear Critical Points
        cpl.locateNuclearCriticalPoints();

        // QLists of results
        QList<qint64>    nucChargeList=wfn.nuclearChargesList();
        QList<QVector3D> ncpList=cpl.nuclearCriticalPoints();

        QVariantList xNCPsVariantList;
        QVariantList yNCPsVariantList;
        QVariantList zNCPsVariantList;
        QVariantList nuclearChargesVariantList;

        const qreal convertBohrToAngstrom=0.529177249;

        // Nuclear Critical Points
        for( qint64 n=0 ; n < ncpList.length() ; ++n )
        {
          QVector3D thisNuclearCriticalPoint=ncpList.at(n);

          qreal x=thisNuclearCriticalPoint.x() * convertBohrToAngstrom;
          qreal y=thisNuclearCriticalPoint.y() * convertBohrToAngstrom;
          qreal z=thisNuclearCriticalPoint.z() * convertBohrToAngstrom;

          xNCPsVariantList.append( x );
          yNCPsVariantList.append( y );
          zNCPsVariantList.append( z );
          nuclearChargesVariantList.append( wfn.nuclearCharge(n) );

        }

        m_molecule->setProperty("QTAIMXNuclearCriticalPoints",xNCPsVariantList);
        m_molecule->setProperty("QTAIMYNuclearCriticalPoints",yNCPsVariantList);
        m_molecule->setProperty("QTAIMZNuclearCriticalPoints",zNCPsVariantList);
        m_molecule->setProperty("QTAIMNuclearCharges",nuclearChargesVariantList);

        // Nuclei stored as Atoms
        for( qint64 n=0 ; n < wfn.numberOfNuclei() ; ++n )
        {
          qreal x=wfn.xNuclearCoordinate(n) * convertBohrToAngstrom;
          qreal y=wfn.yNuclearCoordinate(n) * convertBohrToAngstrom;
          qreal z=wfn.zNuclearCoordinate(n) * convertBohrToAngstrom;

          int Z=(int) wfn.nuclearCharge(n);

          Atom *atom=m_molecule->addAtom();
          atom->setPos( Eigen::Vector3d(x,y,z) );
          atom->setAtomicNumber(Z);
        }

        m_molecule->update();

        // Locate the Bond Critical Points and Trace Bond Paths
        cpl.locateBondCriticalPoints();

        // BCP and Bond Path Results
        QList<QVector3D> bcpList=cpl.bondCriticalPoints();
        QList<QList<QVector3D> > bondPathList=cpl.bondPaths();
        QList<QPair<qint64,qint64> > bondedAtomsList=cpl.bondedAtoms();
        QList<qreal> laplacianAtBondCriticalPoints=cpl.laplacianAtBondCriticalPoints();
        QList<qreal> ellipticityAtBondCriticalPoints=cpl.ellipticityAtBondCriticalPoints();

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

        QList<Atom *> currentAtoms=m_molecule->atoms();

        // Connectivity stored as Bonds

        qint64 bpCtr=0;

        for( qint64 atom0=0 ; atom0 < currentAtoms.length() - 1 ; ++atom0 )
        {
          for( qint64 atom1=atom0+1 ; atom1 < currentAtoms.length() ; ++atom1 )
          {

            bool areBonded=false;

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

                  qreal x=bcpList.at(bondPair).x() * convertBohrToAngstrom;
                  qreal y=bcpList.at(bondPair).y() * convertBohrToAngstrom;
                  qreal z=bcpList.at(bondPair).z() * convertBohrToAngstrom;

                  xBCPsVariantList.append( x );
                  yBCPsVariantList.append( y );
                  zBCPsVariantList.append( z );

                  firstNCPIndexVariantList.append( atom0 );
                  secondNCPIndexVariantList.append( atom1 );

                  laplacianAtBondCriticalPointsVariantList.append( laplacianAtBondCriticalPoints.at(bondPair) );
                  ellipticityAtBondCriticalPointsVariantList.append( ellipticityAtBondCriticalPoints.at(bondPair) );

                  bondPathSegmentStartIndexVariantList.append( bpCtr );
                  for( qint64 i=0; i < bondPathList.at(bondPair).length() ; ++i )
                  {
                    qreal x=bondPathList.at(bondPair).at(i).x() * convertBohrToAngstrom;
                    qreal y=bondPathList.at(bondPair).at(i).y() * convertBohrToAngstrom;
                    qreal z=bondPathList.at(bondPair).at(i).z() * convertBohrToAngstrom;

                    xBondPathsVariantList.append( x );
                    yBondPathsVariantList.append( y );
                    zBondPathsVariantList.append( z );

                    bpCtr++;
                  }
                  bondPathSegmentEndIndexVariantList.append( bpCtr );
                }

              }
            } // bond pairs
          } // atom1
        } // atom 0

        m_molecule->setProperty("QTAIMXBondCriticalPoints",xBCPsVariantList);
        m_molecule->setProperty("QTAIMYBondCriticalPoints",yBCPsVariantList);
        m_molecule->setProperty("QTAIMZBondCriticalPoints",zBCPsVariantList);
        m_molecule->setProperty("QTAIMFirstNCPIndexVariantList",firstNCPIndexVariantList);
        m_molecule->setProperty("QTAIMSecondNCPIndexVariantList",secondNCPIndexVariantList);
        m_molecule->setProperty("QTAIMLaplacianAtBondCriticalPoints",laplacianAtBondCriticalPointsVariantList);
        m_molecule->setProperty("QTAIMEllipticityAtBondCriticalPoints",ellipticityAtBondCriticalPointsVariantList);

        m_molecule->setProperty("QTAIMBondPathSegmentStartIndex",bondPathSegmentStartIndexVariantList);
        m_molecule->setProperty("QTAIMBondPathSegmentEndIndex",bondPathSegmentEndIndexVariantList);
        m_molecule->setProperty("QTAIMXBondPaths",xBondPathsVariantList);
        m_molecule->setProperty("QTAIMYBondPaths",yBondPathsVariantList);
        m_molecule->setProperty("QTAIMZBondPaths",zBondPathsVariantList);

        m_molecule->update();
      }
      break;
    case SecondAction: // Molecular Graph with Lone Pairs
      {
        // Instantiate a Critical Point Locator
        QTAIMCriticalPointLocator cpl(wfn);

        // Locate the Nuclear Critical Points
        cpl.locateNuclearCriticalPoints();

        // QLists of results
        QList<qint64>    nucChargeList=wfn.nuclearChargesList();
        QList<QVector3D> ncpList=cpl.nuclearCriticalPoints();

        QVariantList xNCPsVariantList;
        QVariantList yNCPsVariantList;
        QVariantList zNCPsVariantList;
        QVariantList nuclearChargesVariantList;

        const qreal convertBohrToAngstrom=0.529177249;

        // Nuclear Critical Points
        for( qint64 n=0 ; n < ncpList.length() ; ++n )
        {
          QVector3D thisNuclearCriticalPoint=ncpList.at(n);

          qreal x=thisNuclearCriticalPoint.x() * convertBohrToAngstrom;
          qreal y=thisNuclearCriticalPoint.y() * convertBohrToAngstrom;
          qreal z=thisNuclearCriticalPoint.z() * convertBohrToAngstrom;

          xNCPsVariantList.append( x );
          yNCPsVariantList.append( y );
          zNCPsVariantList.append( z );
          nuclearChargesVariantList.append( wfn.nuclearCharge(n) );

        }

        m_molecule->setProperty("QTAIMXNuclearCriticalPoints",xNCPsVariantList);
        m_molecule->setProperty("QTAIMYNuclearCriticalPoints",yNCPsVariantList);
        m_molecule->setProperty("QTAIMZNuclearCriticalPoints",zNCPsVariantList);
        m_molecule->setProperty("QTAIMNuclearCharges",nuclearChargesVariantList);

        // Nuclei stored as Atoms
        for( qint64 n=0 ; n < wfn.numberOfNuclei() ; ++n )
        {
          qreal x=wfn.xNuclearCoordinate(n) * convertBohrToAngstrom;
          qreal y=wfn.yNuclearCoordinate(n) * convertBohrToAngstrom;
          qreal z=wfn.zNuclearCoordinate(n) * convertBohrToAngstrom;

          int Z=(int) wfn.nuclearCharge(n);

          Atom *atom=m_molecule->addAtom();
          atom->setPos( Eigen::Vector3d(x,y,z) );
          atom->setAtomicNumber(Z);
        }

        m_molecule->update();

        // Locate the Bond Critical Points and Trace Bond Paths
        cpl.locateBondCriticalPoints();

        // BCP and Bond Path Results
        QList<QVector3D> bcpList=cpl.bondCriticalPoints();
        QList<QList<QVector3D> > bondPathList=cpl.bondPaths();
        QList<QPair<qint64,qint64> > bondedAtomsList=cpl.bondedAtoms();
        QList<qreal> laplacianAtBondCriticalPoints=cpl.laplacianAtBondCriticalPoints();
        QList<qreal> ellipticityAtBondCriticalPoints=cpl.ellipticityAtBondCriticalPoints();

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

        QList<Atom *> currentAtoms=m_molecule->atoms();

        // Connectivity stored as Bonds

        qint64 bpCtr=0;

        for( qint64 atom0=0 ; atom0 < currentAtoms.length() - 1 ; ++atom0 )
        {
          for( qint64 atom1=atom0+1 ; atom1 < currentAtoms.length() ; ++atom1 )
          {

            bool areBonded=false;

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

                  qreal x=bcpList.at(bondPair).x() * convertBohrToAngstrom;
                  qreal y=bcpList.at(bondPair).y() * convertBohrToAngstrom;
                  qreal z=bcpList.at(bondPair).z() * convertBohrToAngstrom;

                  xBCPsVariantList.append( x );
                  yBCPsVariantList.append( y );
                  zBCPsVariantList.append( z );

                  firstNCPIndexVariantList.append( atom0 );
                  secondNCPIndexVariantList.append( atom1 );

                  laplacianAtBondCriticalPointsVariantList.append( laplacianAtBondCriticalPoints.at(bondPair) );
                  ellipticityAtBondCriticalPointsVariantList.append( ellipticityAtBondCriticalPoints.at(bondPair) );

                  bondPathSegmentStartIndexVariantList.append( bpCtr );
                  for( qint64 i=0; i < bondPathList.at(bondPair).length() ; ++i )
                  {
                    qreal x=bondPathList.at(bondPair).at(i).x() * convertBohrToAngstrom;
                    qreal y=bondPathList.at(bondPair).at(i).y() * convertBohrToAngstrom;
                    qreal z=bondPathList.at(bondPair).at(i).z() * convertBohrToAngstrom;

                    xBondPathsVariantList.append( x );
                    yBondPathsVariantList.append( y );
                    zBondPathsVariantList.append( z );

                    bpCtr++;
                  }
                  bondPathSegmentEndIndexVariantList.append( bpCtr );
                }

              }
            } // bond pairs
          } // atom1
        } // atom 0

        m_molecule->setProperty("QTAIMXBondCriticalPoints",xBCPsVariantList);
        m_molecule->setProperty("QTAIMYBondCriticalPoints",yBCPsVariantList);
        m_molecule->setProperty("QTAIMZBondCriticalPoints",zBCPsVariantList);
        m_molecule->setProperty("QTAIMFirstNCPIndexVariantList",firstNCPIndexVariantList);
        m_molecule->setProperty("QTAIMSecondNCPIndexVariantList",secondNCPIndexVariantList);
        m_molecule->setProperty("QTAIMLaplacianAtBondCriticalPoints",laplacianAtBondCriticalPointsVariantList);
        m_molecule->setProperty("QTAIMEllipticityAtBondCriticalPoints",ellipticityAtBondCriticalPointsVariantList);

        m_molecule->setProperty("QTAIMBondPathSegmentStartIndex",bondPathSegmentStartIndexVariantList);
        m_molecule->setProperty("QTAIMBondPathSegmentEndIndex",bondPathSegmentEndIndexVariantList);
        m_molecule->setProperty("QTAIMXBondPaths",xBondPathsVariantList);
        m_molecule->setProperty("QTAIMYBondPaths",yBondPathsVariantList);
        m_molecule->setProperty("QTAIMZBondPaths",zBondPathsVariantList);

        m_molecule->update();

        // Locate Electron Density Sources / Lone Pairs

        cpl.locateElectronDensitySources();
        QList<QVector3D> electronDensitySourcesList=cpl.electronDensitySources();

        QVariantList xElectronDensitySourcesVariantList;
        QVariantList yElectronDensitySourcesVariantList;
        QVariantList zElectronDensitySourcesVariantList;

        for( qint64 n=0 ; n < electronDensitySourcesList.length() ; ++n )
        {
          QVector3D thisCriticalPoint=electronDensitySourcesList.at(n);

          qreal x=thisCriticalPoint.x() * convertBohrToAngstrom;
          qreal y=thisCriticalPoint.y() * convertBohrToAngstrom;
          qreal z=thisCriticalPoint.z() * convertBohrToAngstrom;

          xElectronDensitySourcesVariantList.append( x );
          yElectronDensitySourcesVariantList.append( y );
          zElectronDensitySourcesVariantList.append( z );

        }

        m_molecule->setProperty("QTAIMXElectronDensitySources",xElectronDensitySourcesVariantList);
        m_molecule->setProperty("QTAIMYElectronDensitySources",yElectronDensitySourcesVariantList);
        m_molecule->setProperty("QTAIMZElectronDensitySources",zElectronDensitySourcesVariantList);

        m_molecule->update();

      }
      break;
    case ThirdAction:
      // perform third action
      {
        // Instantiate a Critical Point Locator
        QTAIMCriticalPointLocator cpl(wfn);

        // Locate the Nuclear Critical Points
        cpl.locateNuclearCriticalPoints();

        // QLists of results
        QList<qint64>    nucChargeList=wfn.nuclearChargesList();
        QList<QVector3D> ncpList=cpl.nuclearCriticalPoints();

        QVariantList xNCPsVariantList;
        QVariantList yNCPsVariantList;
        QVariantList zNCPsVariantList;
        QVariantList nuclearChargesVariantList;

        const qreal convertBohrToAngstrom=0.529177249;

        // Nuclear Critical Points
        for( qint64 n=0 ; n < ncpList.length() ; ++n )
        {
          QVector3D thisNuclearCriticalPoint=ncpList.at(n);

          qreal x=thisNuclearCriticalPoint.x() * convertBohrToAngstrom;
          qreal y=thisNuclearCriticalPoint.y() * convertBohrToAngstrom;
          qreal z=thisNuclearCriticalPoint.z() * convertBohrToAngstrom;

          xNCPsVariantList.append( x );
          yNCPsVariantList.append( y );
          zNCPsVariantList.append( z );
          nuclearChargesVariantList.append( wfn.nuclearCharge(n) );

        }

        m_molecule->setProperty("QTAIMXNuclearCriticalPoints",xNCPsVariantList);
        m_molecule->setProperty("QTAIMYNuclearCriticalPoints",yNCPsVariantList);
        m_molecule->setProperty("QTAIMZNuclearCriticalPoints",zNCPsVariantList);
        m_molecule->setProperty("QTAIMNuclearCharges",nuclearChargesVariantList);

        // Nuclei stored as Atoms
        for( qint64 n=0 ; n < wfn.numberOfNuclei() ; ++n )
        {
          qreal x=wfn.xNuclearCoordinate(n) * convertBohrToAngstrom;
          qreal y=wfn.yNuclearCoordinate(n) * convertBohrToAngstrom;
          qreal z=wfn.zNuclearCoordinate(n) * convertBohrToAngstrom;

          int Z=(int) wfn.nuclearCharge(n);

          Atom *atom=m_molecule->addAtom();
          atom->setPos( Eigen::Vector3d(x,y,z) );
          atom->setAtomicNumber(Z);
        }

        m_molecule->update();

        // Locate the Bond Critical Points and Trace Bond Paths
        cpl.locateBondCriticalPoints();

        // BCP and Bond Path Results
        QList<QVector3D> bcpList=cpl.bondCriticalPoints();
        QList<QList<QVector3D> > bondPathList=cpl.bondPaths();
        QList<QPair<qint64,qint64> > bondedAtomsList=cpl.bondedAtoms();
        QList<qreal> laplacianAtBondCriticalPoints=cpl.laplacianAtBondCriticalPoints();
        QList<qreal> ellipticityAtBondCriticalPoints=cpl.ellipticityAtBondCriticalPoints();

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

        QList<Atom *> currentAtoms=m_molecule->atoms();

        // Connectivity stored as Bonds

        qint64 bpCtr=0;

        for( qint64 atom0=0 ; atom0 < currentAtoms.length() - 1 ; ++atom0 )
        {
          for( qint64 atom1=atom0+1 ; atom1 < currentAtoms.length() ; ++atom1 )
          {

            bool areBonded=false;

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

                  qreal x=bcpList.at(bondPair).x() * convertBohrToAngstrom;
                  qreal y=bcpList.at(bondPair).y() * convertBohrToAngstrom;
                  qreal z=bcpList.at(bondPair).z() * convertBohrToAngstrom;

                  xBCPsVariantList.append( x );
                  yBCPsVariantList.append( y );
                  zBCPsVariantList.append( z );

                  firstNCPIndexVariantList.append( atom0 );
                  secondNCPIndexVariantList.append( atom1 );

                  laplacianAtBondCriticalPointsVariantList.append( laplacianAtBondCriticalPoints.at(bondPair) );
                  ellipticityAtBondCriticalPointsVariantList.append( ellipticityAtBondCriticalPoints.at(bondPair) );

                  bondPathSegmentStartIndexVariantList.append( bpCtr );
                  for( qint64 i=0; i < bondPathList.at(bondPair).length() ; ++i )
                  {
                    qreal x=bondPathList.at(bondPair).at(i).x() * convertBohrToAngstrom;
                    qreal y=bondPathList.at(bondPair).at(i).y() * convertBohrToAngstrom;
                    qreal z=bondPathList.at(bondPair).at(i).z() * convertBohrToAngstrom;

                    xBondPathsVariantList.append( x );
                    yBondPathsVariantList.append( y );
                    zBondPathsVariantList.append( z );

                    bpCtr++;
                  }
                  bondPathSegmentEndIndexVariantList.append( bpCtr );
                }

              }
            } // bond pairs
          } // atom1
        } // atom 0

        m_molecule->setProperty("QTAIMXBondCriticalPoints",xBCPsVariantList);
        m_molecule->setProperty("QTAIMYBondCriticalPoints",yBCPsVariantList);
        m_molecule->setProperty("QTAIMZBondCriticalPoints",zBCPsVariantList);
        m_molecule->setProperty("QTAIMFirstNCPIndexVariantList",firstNCPIndexVariantList);
        m_molecule->setProperty("QTAIMSecondNCPIndexVariantList",secondNCPIndexVariantList);
        m_molecule->setProperty("QTAIMLaplacianAtBondCriticalPoints",laplacianAtBondCriticalPointsVariantList);
        m_molecule->setProperty("QTAIMEllipticityAtBondCriticalPoints",ellipticityAtBondCriticalPointsVariantList);

        m_molecule->setProperty("QTAIMBondPathSegmentStartIndex",bondPathSegmentStartIndexVariantList);
        m_molecule->setProperty("QTAIMBondPathSegmentEndIndex",bondPathSegmentEndIndexVariantList);
        m_molecule->setProperty("QTAIMXBondPaths",xBondPathsVariantList);
        m_molecule->setProperty("QTAIMYBondPaths",yBondPathsVariantList);
        m_molecule->setProperty("QTAIMZBondPaths",zBondPathsVariantList);

        m_molecule->update();

        // Electron Density
        qint64 mode=0;

        // All Atomic Basins
        QList<qint64> basins;
        for( qint64 i=0 ; i < wfn.numberOfNuclei() ; ++i )
        {
          basins.append(i);
        }

        QTAIMCubature cub(wfn);

        //        QTime time;
        //        time.start();
        QList<QPair<qreal,qreal> > results=cub.integrate(mode,basins);
        //        qDebug() << "Time Elapsed:" << time.elapsed();

        for(qint64 i=0 ; i < results.length() ; ++i)
        {
          qDebug() << "basin" << i << results.at(i).first << results.at(i).second;
        }

        // TODO: Set the properties of the atoms.
        // I don't know why this bombs.
        for(qint64 i=0 ; m_molecule->atoms().length(); ++i)
        {
//          Atom *atom=m_molecule->atoms().at(i);
//          const qreal charge=results.at(i).first;
//          atom->setPartialCharge( charge  );
        }

      }
      break;
    }

    return 0;
  }

}

Q_EXPORT_PLUGIN2(qtaimextension, Avogadro::QTAIMExtensionFactory)

