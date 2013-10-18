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

#include <QDebug>
#include <QString>
#include <QStringList>
#include <QFile>
#include <QTextStream>

#include "qtaimwavefunction.h"

namespace Avogadro
{
  QTAIMWavefunction::QTAIMWavefunction()
  {
    m_initializationSuccessful = false;
  }

  bool QTAIMWavefunction::initializeWithWFNFile(const QString &fileName)
  {

    m_initializationSuccessful = false;

    QFile file(fileName);
    bool fileExists = file.exists();

    if( !(fileExists) )
    {
      m_initializationSuccessful = false;
      m_fileDoesNotExist = true;
      return m_initializationSuccessful;
    }
    else
    {
      m_fileDoesNotExist = false;
    }

    bool success;
    success=file.open(QIODevice::ReadOnly | QIODevice::Text);

    if( !(success) )
    {
      m_initializationSuccessful = false;
      m_ioError = true;
      return m_initializationSuccessful;
    }
    else
    {
      m_ioError = false;
    }

    m_fileName=fileName;

    QTextStream in(&file);
    QString fileContents=in.readAll();

    file.close();

    QStringList fileContentsByLine(fileContents.split("\n"));

    // Title/Comment
    m_comment=fileContentsByLine.first();
    fileContentsByLine.removeFirst();

    m_numberOfMolecularOrbitals=fileContentsByLine.first().mid(8,15).toLongLong();
    m_numberOfGaussianPrimitives=fileContentsByLine.first().mid(36,8).toLongLong();;
    m_numberOfNuclei=fileContentsByLine.first().mid(54,10).toLongLong();;
    fileContentsByLine.removeFirst();

    // Maximum Number of Nuclei Due to Fixed Format
    if( m_numberOfNuclei > 999 )
    {
      m_initializationSuccessful = false;
      m_tooManyNuclei = true;
      return m_initializationSuccessful;
    }
    else
    {
      m_tooManyNuclei = false ;
    }

    m_xNuclearCoordinates.resize(m_numberOfNuclei);
    m_yNuclearCoordinates.resize(m_numberOfNuclei);
    m_zNuclearCoordinates.resize(m_numberOfNuclei);
    m_nuclearCharges.resize(m_numberOfNuclei);

    for( qint64 i=0; i < m_numberOfNuclei ; ++i )
    {
      m_xNuclearCoordinates[i]=fileContentsByLine.first().mid(24,13).toDouble();
      m_yNuclearCoordinates[i]=fileContentsByLine.first().mid(36,12).toDouble();
      m_zNuclearCoordinates[i]=fileContentsByLine.first().mid(48,12).toDouble();
      m_nuclearCharges[i]=fileContentsByLine.first().mid(70,3).toLongLong();
      fileContentsByLine.removeFirst();
    }


    QList<qint64> centerAssignmentsList;

    while( fileContentsByLine.first().startsWith("CENTRE ASSIGNMENTS")  )
    {
      QString line( fileContentsByLine.first().mid(20,-1) );

      qint64 counter=0;
      while( counter < line.length() )
      {
        centerAssignmentsList.append( line.mid(counter,3).toLongLong() );
        counter=counter+3;
      }

      fileContentsByLine.removeFirst();
    }

    m_xGaussianPrimitiveCenterCoordinates.resize(m_numberOfGaussianPrimitives);
    m_yGaussianPrimitiveCenterCoordinates.resize(m_numberOfGaussianPrimitives);
    m_zGaussianPrimitiveCenterCoordinates.resize(m_numberOfGaussianPrimitives);

    for( qint64 i=0 ; i < m_numberOfGaussianPrimitives ; ++i )
    {
      m_xGaussianPrimitiveCenterCoordinates[i]=m_xNuclearCoordinates[ centerAssignmentsList.at(i) - 1];
      m_yGaussianPrimitiveCenterCoordinates[i]=m_yNuclearCoordinates[ centerAssignmentsList.at(i) - 1];
      m_zGaussianPrimitiveCenterCoordinates[i]=m_zNuclearCoordinates[ centerAssignmentsList.at(i) - 1];
    }


    QList<qint64> typeAssignmentsList;

    while( fileContentsByLine.first().startsWith("TYPE ASSIGNMENTS")  )
    {
      QString line( fileContentsByLine.first().mid(20,-1) );
      QStringList splitLine( line.split(" ", QString::SkipEmptyParts) );

      for( qint64 i=0 ; i < splitLine.length() ; ++i )
      {
        typeAssignmentsList.append( splitLine.at(i).toLongLong() );
      }

      fileContentsByLine.removeFirst();
    }

    m_xGaussianPrimitiveAngularMomenta.resize(m_numberOfGaussianPrimitives);
    m_yGaussianPrimitiveAngularMomenta.resize(m_numberOfGaussianPrimitives);
    m_zGaussianPrimitiveAngularMomenta.resize(m_numberOfGaussianPrimitives);

    for( qint64 i=0 ; i < m_numberOfGaussianPrimitives ; ++i )
    {
      switch(typeAssignmentsList.at(i))
      {
      case 1:
        m_xGaussianPrimitiveAngularMomenta[i]=0;
        m_yGaussianPrimitiveAngularMomenta[i]=0;
        m_zGaussianPrimitiveAngularMomenta[i]=0;
        break;
      case 2:
        m_xGaussianPrimitiveAngularMomenta[i]=1;
        m_yGaussianPrimitiveAngularMomenta[i]=0;
        m_zGaussianPrimitiveAngularMomenta[i]=0;
        break;
      case 3:
        m_xGaussianPrimitiveAngularMomenta[i]=0;
        m_yGaussianPrimitiveAngularMomenta[i]=1;
        m_zGaussianPrimitiveAngularMomenta[i]=0;
        break;
      case 4:
        m_xGaussianPrimitiveAngularMomenta[i]=0;
        m_yGaussianPrimitiveAngularMomenta[i]=0;
        m_zGaussianPrimitiveAngularMomenta[i]=1;
        break;
      case 5:
        m_xGaussianPrimitiveAngularMomenta[i]=2;
        m_yGaussianPrimitiveAngularMomenta[i]=0;
        m_zGaussianPrimitiveAngularMomenta[i]=0;
        break;
      case 6:
        m_xGaussianPrimitiveAngularMomenta[i]=0;
        m_yGaussianPrimitiveAngularMomenta[i]=2;
        m_zGaussianPrimitiveAngularMomenta[i]=0;
        break;
      case 7:
        m_xGaussianPrimitiveAngularMomenta[i]=0;
        m_yGaussianPrimitiveAngularMomenta[i]=0;
        m_zGaussianPrimitiveAngularMomenta[i]=2;
        break;
      case 8:
        m_xGaussianPrimitiveAngularMomenta[i]=1;
        m_yGaussianPrimitiveAngularMomenta[i]=1;
        m_zGaussianPrimitiveAngularMomenta[i]=0;
        break;
      case 9:
        m_xGaussianPrimitiveAngularMomenta[i]=1;
        m_yGaussianPrimitiveAngularMomenta[i]=0;
        m_zGaussianPrimitiveAngularMomenta[i]=1;
        break;
      case 10:
        m_xGaussianPrimitiveAngularMomenta[i]=0;
        m_yGaussianPrimitiveAngularMomenta[i]=1;
        m_zGaussianPrimitiveAngularMomenta[i]=1;
        break;
      case 11:
        m_xGaussianPrimitiveAngularMomenta[i]=3;
        m_yGaussianPrimitiveAngularMomenta[i]=0;
        m_zGaussianPrimitiveAngularMomenta[i]=0;
        break;
      case 12:
        m_xGaussianPrimitiveAngularMomenta[i]=0;
        m_yGaussianPrimitiveAngularMomenta[i]=3;
        m_zGaussianPrimitiveAngularMomenta[i]=0;
        break;
      case 13:
        m_xGaussianPrimitiveAngularMomenta[i]=0;
        m_yGaussianPrimitiveAngularMomenta[i]=0;
        m_zGaussianPrimitiveAngularMomenta[i]=3;
        break;
      case 14:
        m_xGaussianPrimitiveAngularMomenta[i]=2;
        m_yGaussianPrimitiveAngularMomenta[i]=1;
        m_zGaussianPrimitiveAngularMomenta[i]=0;
        break;
      case 15:
        m_xGaussianPrimitiveAngularMomenta[i]=2;
        m_yGaussianPrimitiveAngularMomenta[i]=0;
        m_zGaussianPrimitiveAngularMomenta[i]=1;
        break;
      case 16:
        m_xGaussianPrimitiveAngularMomenta[i]=0;
        m_yGaussianPrimitiveAngularMomenta[i]=2;
        m_zGaussianPrimitiveAngularMomenta[i]=1;
        break;
      case 17:
        m_xGaussianPrimitiveAngularMomenta[i]=1;
        m_yGaussianPrimitiveAngularMomenta[i]=2;
        m_zGaussianPrimitiveAngularMomenta[i]=0;
        break;
      case 18:
        m_xGaussianPrimitiveAngularMomenta[i]=1;
        m_yGaussianPrimitiveAngularMomenta[i]=0;
        m_zGaussianPrimitiveAngularMomenta[i]=2;
        break;
      case 19:
        m_xGaussianPrimitiveAngularMomenta[i]=0;
        m_yGaussianPrimitiveAngularMomenta[i]=1;
        m_zGaussianPrimitiveAngularMomenta[i]=2;
        break;
      case 20:
        m_xGaussianPrimitiveAngularMomenta[i]=1;
        m_yGaussianPrimitiveAngularMomenta[i]=1;
        m_zGaussianPrimitiveAngularMomenta[i]=1;
        break;
      default:
        m_initializationSuccessful=false;
        m_maximumAngularMomentumExceeded=true;
        return m_initializationSuccessful;
      }
    }
    m_maximumAngularMomentumExceeded=false;


    QList<qreal> exponentsList;

    while( fileContentsByLine.first().startsWith("EXPONENTS")  )
    {
      QString line( fileContentsByLine.first().mid(9,-1) );
      QStringList splitLine( line.split(" ", QString::SkipEmptyParts) );

      for( qint64 i=0 ; i < splitLine.length() ; ++i )
      {
        QString str( splitLine.at(i) );
        QString replacedString( str.replace("d","e",Qt::CaseSensitive).replace("D","e",Qt::CaseSensitive).replace("E","e",Qt::CaseSensitive) );
        exponentsList.append( replacedString.toDouble() );
      }

      fileContentsByLine.removeFirst();
    }

    m_gaussianPrimitiveExponentCoefficients.resize(m_numberOfGaussianPrimitives);

    for( qint64 i=0 ; i < m_numberOfGaussianPrimitives ; ++i)
    {
      m_gaussianPrimitiveExponentCoefficients[i]=exponentsList.at(i);
    }

    m_totalEnergy = fileContentsByLine.last().mid(17,20).toDouble();
    m_virialRatio = fileContentsByLine.last().mid(55,-1).toDouble();

    fileContentsByLine.removeLast();
    fileContentsByLine.removeLast();
    if(fileContentsByLine.last().trimmed().contains("END DATA",Qt::CaseSensitive)) fileContentsByLine.removeLast();

    QStringList moHeaderStringList;
    QStringList moCoefficientsStringList;

    QList<qreal> moCoefficientsList;

    for( qint64 i=0; i< fileContentsByLine.length(); ++i)
    {
      if( fileContentsByLine.at(i).trimmed().startsWith("MO") )
      {
        moHeaderStringList.append( fileContentsByLine.at(i) );
      }
      else
      {
        moCoefficientsStringList.append( fileContentsByLine.at(i) );
      }
    }

    QList<qreal> molecularOrbitalOccupationNumbersList;
    QList<qreal> molecularOrbitalEigenvaluesList;

    for( qint64 i=0; i < moHeaderStringList.length() ; ++i)
    {
      molecularOrbitalOccupationNumbersList.append( moHeaderStringList.at(i).mid(34,13).toDouble() );
      molecularOrbitalEigenvaluesList.append( moHeaderStringList.at(i).mid(62,-1).toDouble() );
    }

    m_molecularOrbitalOccupationNumbers.resize(m_numberOfMolecularOrbitals);

    for( qint64 i=0; i < m_numberOfMolecularOrbitals ; ++i )
      m_molecularOrbitalOccupationNumbers[i]=molecularOrbitalOccupationNumbersList.at(i);

    m_molecularOrbitalEigenvalues.resize(m_numberOfMolecularOrbitals);

    for( qint64 i=0; i < m_numberOfMolecularOrbitals ; ++i )
      m_molecularOrbitalEigenvalues[i]=molecularOrbitalEigenvaluesList.at(i);

    moCoefficientsStringList=moCoefficientsStringList.join(" ").split(" ", QString::SkipEmptyParts);

    for( qint64 i=0; i < moCoefficientsStringList.length() ; ++i)
    {
      QString str( moCoefficientsStringList.at(i) );
      QString replacedString( str.replace("d","e",Qt::CaseSensitive).replace("D","e",Qt::CaseSensitive).replace("E","e",Qt::CaseSensitive) );

      moCoefficientsList.append( replacedString.toDouble() );
    }

    m_molecularOrbitalCoefficients.resize( m_numberOfMolecularOrbitals * m_numberOfGaussianPrimitives );

    for( qint64 i=0; i < (m_numberOfMolecularOrbitals * m_numberOfGaussianPrimitives) ; ++i )
      m_molecularOrbitalCoefficients[i]=moCoefficientsList.at(i);

    m_initializationSuccessful = true;

    return m_initializationSuccessful;

  }

  bool QTAIMWavefunction::initializeWithMoleculeProperties( Molecule*& mol )
  {

    if( mol->property( "QTAIMNumberOfMolecularOrbitals" ).isValid() )
    {

      QVariant numberOfMolecularOrbitalsVariant = mol->property( "QTAIMNumberOfMolecularOrbitals" );
      m_numberOfMolecularOrbitals=numberOfMolecularOrbitalsVariant.toLongLong();

      QVariant numberOfGaussianPrimitivesVariant = mol->property( "QTAIMNumberOfGaussianPrimitives" );
      m_numberOfGaussianPrimitives=numberOfGaussianPrimitivesVariant.toLongLong();

      QVariant numberOfNucleiVariant = mol->property( "QTAIMNumberOfNuclei" );
      m_numberOfNuclei=numberOfNucleiVariant.toLongLong();

      QVariant xNuclearCoordinatesVariant = mol->property( "QTAIMXNuclearCoordinates");
      QVariant yNuclearCoordinatesVariant = mol->property( "QTAIMYNuclearCoordinates");
      QVariant zNuclearCoordinatesVariant = mol->property( "QTAIMZNuclearCoordinates");
      QVariant nuclearChargesVariant = mol->property( "QTAIMNuclearCharges" );
      QVariantList xNuclearCoordinatesVariantList = xNuclearCoordinatesVariant.toList();
      QVariantList yNuclearCoordinatesVariantList = yNuclearCoordinatesVariant.toList();
      QVariantList zNuclearCoordinatesVariantList = zNuclearCoordinatesVariant.toList();
      QVariantList nuclearChargesVariantList = nuclearChargesVariant.toList();
      QList<qreal> xNuclearCoordinatesList;
      QList<qreal> yNuclearCoordinatesList;
      QList<qreal> zNuclearCoordinatesList;
      QList<qint64> nuclearChargesList;
      for( qint64 i=0 ; i < m_numberOfNuclei ; ++i )
      {
        xNuclearCoordinatesList.append( xNuclearCoordinatesVariantList.at(i).toReal() );
        yNuclearCoordinatesList.append( yNuclearCoordinatesVariantList.at(i).toReal() );
        zNuclearCoordinatesList.append( zNuclearCoordinatesVariantList.at(i).toReal() );
        nuclearChargesList.append( nuclearChargesVariantList.at(i).toLongLong() );
      }
      m_xNuclearCoordinates=xNuclearCoordinatesList.toVector();
      m_yNuclearCoordinates=yNuclearCoordinatesList.toVector();
      m_zNuclearCoordinates=zNuclearCoordinatesList.toVector();
      m_nuclearCharges=nuclearChargesList.toVector();

      QVariant xGaussianPrimitiveCenterCoordinatesVariant = mol->property( "QTAIMXGaussianPrimitiveCenterCoordinates" );
      QVariant yGaussianPrimitiveCenterCoordinatesVariant = mol->property( "QTAIMYGaussianPrimitiveCenterCoordinates" );
      QVariant zGaussianPrimitiveCenterCoordinatesVariant = mol->property( "QTAIMZGaussianPrimitiveCenterCoordinates" );
      QVariant xGaussianPrimitiveAngularMomentaVariant = mol->property( "QTAIMXGaussianPrimitiveAngularMomenta" );
      QVariant yGaussianPrimitiveAngularMomentaVariant = mol->property( "QTAIMYGaussianPrimitiveAngularMomenta" );
      QVariant zGaussianPrimitiveAngularMomentaVariant = mol->property( "QTAIMZGaussianPrimitiveAngularMomenta" );
      QVariant gaussianPrimitiveExponentCoefficientsVariant = mol->property( "QTAIMGaussianPrimitiveExponentCoefficients" );
      QVariantList xGaussianPrimitiveCenterCoordinatesVariantList = xGaussianPrimitiveCenterCoordinatesVariant.toList();
      QVariantList yGaussianPrimitiveCenterCoordinatesVariantList = yGaussianPrimitiveCenterCoordinatesVariant.toList();
      QVariantList zGaussianPrimitiveCenterCoordinatesVariantList = zGaussianPrimitiveCenterCoordinatesVariant.toList();
      QVariantList xGaussianPrimitiveAngularMomentaVariantList = xGaussianPrimitiveAngularMomentaVariant.toList();
      QVariantList yGaussianPrimitiveAngularMomentaVariantList = yGaussianPrimitiveAngularMomentaVariant.toList();
      QVariantList zGaussianPrimitiveAngularMomentaVariantList = zGaussianPrimitiveAngularMomentaVariant.toList();
      QVariantList gaussianPrimitiveExponentCoefficientsVariantList = gaussianPrimitiveExponentCoefficientsVariant.toList();
      QList<qreal> xGaussianPrimitiveCenterCoordinatesList;
      QList<qreal> yGaussianPrimitiveCenterCoordinatesList;
      QList<qreal> zGaussianPrimitiveCenterCoordinatesList;
      QList<qint64> xGaussianPrimitiveAngularMomentaList;
      QList<qint64> yGaussianPrimitiveAngularMomentaList;
      QList<qint64> zGaussianPrimitiveAngularMomentaList;
      QList<qreal> gaussianPrimitiveExponentCoefficientsList;

      for( qint64 p=0 ; p < m_numberOfGaussianPrimitives ; ++p )
      {
        xGaussianPrimitiveCenterCoordinatesList.append(xGaussianPrimitiveCenterCoordinatesVariantList.at(p).toReal());
        yGaussianPrimitiveCenterCoordinatesList.append(yGaussianPrimitiveCenterCoordinatesVariantList.at(p).toReal());
        zGaussianPrimitiveCenterCoordinatesList.append(zGaussianPrimitiveCenterCoordinatesVariantList.at(p).toReal());
        xGaussianPrimitiveAngularMomentaList.append(xGaussianPrimitiveAngularMomentaVariantList.at(p).toLongLong());
        yGaussianPrimitiveAngularMomentaList.append(yGaussianPrimitiveAngularMomentaVariantList.at(p).toLongLong());
        zGaussianPrimitiveAngularMomentaList.append(zGaussianPrimitiveAngularMomentaVariantList.at(p).toLongLong());
        gaussianPrimitiveExponentCoefficientsList.append(gaussianPrimitiveExponentCoefficientsVariantList.at(p).toReal());
      }

      m_xGaussianPrimitiveCenterCoordinates=xGaussianPrimitiveCenterCoordinatesList.toVector();
      m_yGaussianPrimitiveCenterCoordinates=yGaussianPrimitiveCenterCoordinatesList.toVector();
      m_zGaussianPrimitiveCenterCoordinates=zGaussianPrimitiveCenterCoordinatesList.toVector();
      m_xGaussianPrimitiveAngularMomenta=xGaussianPrimitiveAngularMomentaList.toVector();
      m_yGaussianPrimitiveAngularMomenta=yGaussianPrimitiveAngularMomentaList.toVector();
      m_zGaussianPrimitiveAngularMomenta=zGaussianPrimitiveAngularMomentaList.toVector();
      m_gaussianPrimitiveExponentCoefficients=gaussianPrimitiveExponentCoefficientsList.toVector();

      QVariant molecularOrbitalOccupationNumbersVariant = mol->property( "QTAIMMolecularOrbitalOccupationNumbers" );
      QVariant molecularOrbitalEigenvaluesVariant = mol->property( "QTAIMMolecularOrbitalEigenvalues" );
      QVariant molecularOrbitalCoefficientsVariant = mol->property( "QTAIMMolecularOrbitalCoefficients" );
      QVariantList molecularOrbitalOccupationNumbersVariantList = molecularOrbitalOccupationNumbersVariant.toList();
      QVariantList molecularOrbitalEigenvaluesVariantList = molecularOrbitalEigenvaluesVariant.toList();
      QVariantList molecularOrbitalCoefficientsVariantList = molecularOrbitalCoefficientsVariant.toList();
      QList<qreal> molecularOrbitalOccupationNumbersList;
      QList<qreal> molecularOrbitalEigenvaluesList;
      QList<qreal> molecularOrbitalCoefficientsList;

      for( qint64 m=0; m < m_numberOfMolecularOrbitals ; ++m )
      {
        molecularOrbitalOccupationNumbersList.append(molecularOrbitalOccupationNumbersVariantList.at(m).toReal());
        molecularOrbitalEigenvaluesList.append(molecularOrbitalEigenvaluesVariantList.at(m).toReal());
      }

      for( qint64 i=0; i < (m_numberOfMolecularOrbitals * m_numberOfGaussianPrimitives) ; ++i)
      {
        molecularOrbitalCoefficientsList.append(molecularOrbitalCoefficientsVariantList.at(i).toReal());
      }

      m_molecularOrbitalOccupationNumbers=molecularOrbitalOccupationNumbersList.toVector();
      m_molecularOrbitalEigenvalues=molecularOrbitalEigenvaluesList.toVector();
      m_molecularOrbitalCoefficients=molecularOrbitalCoefficientsList.toVector();

      QVariant totalEnergyVariant = mol->property("QTAIMTotalEnergy");
      QVariant virialRatioVariant = mol->property("QTAIMVirialRatio");

      m_totalEnergy=totalEnergyVariant.toReal();
      m_virialRatio=virialRatioVariant.toReal();

    }

    return true;
  }

}
