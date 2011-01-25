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

#ifndef QTAIMWAVEFUNCTION_H
#define QTAIMWAVEFUNCTION_H

#include <QObject>
#include <QString>
#include <QVector>
#include <QList>

#include <QFile>
#include <QIODevice>
#include <QDataStream>

#include <QVariant>
#include <QVariantList>

#include <avogadro/molecule.h>

namespace Avogadro
{

  class QTAIMWavefunctionEvaluator;

  class QTAIMWavefunction
  {

  public:
    explicit QTAIMWavefunction();

    void saveToBinaryFile(const QString &fileName)
    {
      QFile file(fileName);
      file.open(QIODevice::WriteOnly);
      QDataStream out(&file);
      out << m_fileName;
      out << m_comment;
      out << m_numberOfMolecularOrbitals;
      out << m_numberOfGaussianPrimitives;
      out << m_numberOfNuclei;
      out << m_xNuclearCoordinates;
      out << m_yNuclearCoordinates;
      out << m_zNuclearCoordinates;
      out << m_nuclearCharges;
      out << m_xGaussianPrimitiveCenterCoordinates;
      out << m_yGaussianPrimitiveCenterCoordinates;
      out << m_zGaussianPrimitiveCenterCoordinates;
      out << m_xGaussianPrimitiveAngularMomenta;
      out << m_yGaussianPrimitiveAngularMomenta;
      out << m_zGaussianPrimitiveAngularMomenta;
      out << m_gaussianPrimitiveExponentCoefficients;
      out << m_molecularOrbitalOccupationNumbers;
      out << m_molecularOrbitalEigenvalues;
      out << m_molecularOrbitalCoefficients;
      out << m_totalEnergy;
      out << m_virialRatio;
    }

    void loadFromBinaryFile(const QString &fileName)
    {
      QFile file(fileName);
      file.open(QIODevice::ReadOnly);
      QDataStream in(&file);
      in >> m_fileName;
      in >> m_comment;
      in >> m_numberOfMolecularOrbitals;
      in >> m_numberOfGaussianPrimitives;
      in >> m_numberOfNuclei;
      in >> m_xNuclearCoordinates;
      in >> m_yNuclearCoordinates;
      in >> m_zNuclearCoordinates;
      in >> m_nuclearCharges;
      in >> m_xGaussianPrimitiveCenterCoordinates;
      in >> m_yGaussianPrimitiveCenterCoordinates;
      in >> m_zGaussianPrimitiveCenterCoordinates;
      in >> m_xGaussianPrimitiveAngularMomenta;
      in >> m_yGaussianPrimitiveAngularMomenta;
      in >> m_zGaussianPrimitiveAngularMomenta;
      in >> m_gaussianPrimitiveExponentCoefficients;
      in >> m_molecularOrbitalOccupationNumbers;
      in >> m_molecularOrbitalEigenvalues;
      in >> m_molecularOrbitalCoefficients;
      in >> m_totalEnergy;
      in >> m_virialRatio;
    }

    bool initializeWithWFNFile(const QString &fileName);
//    bool initializeWithMoleculeProperties( Molecule &mol );
    bool initializeWithMoleculeProperties( Molecule*& mol );
    // TODO initialize with Avogadro general wavefunction

    qint64 numberOfMolecularOrbitals() const { return m_numberOfMolecularOrbitals; }
    qint64 numberOfGaussianPrimitives() const { return m_numberOfGaussianPrimitives; }
    qint64 numberOfNuclei() const { return m_numberOfNuclei; }

    const qreal* xNuclearCoordinates() const { return m_xNuclearCoordinates.constData(); }
    const qreal* yNuclearCoordinates() const { return m_yNuclearCoordinates.constData(); }
    const qreal* zNuclearCoordinates() const { return m_zNuclearCoordinates.constData(); }
    qreal xNuclearCoordinate( qint64 i ) const { return m_xNuclearCoordinates.at(i); }
    qreal yNuclearCoordinate( qint64 i ) const { return m_yNuclearCoordinates.at(i); }
    qreal zNuclearCoordinate( qint64 i ) const { return m_zNuclearCoordinates.at(i); }

    const qint64* nuclearCharges() const { return m_nuclearCharges.constData(); }
    qint64 nuclearCharge( qint64 i ) const { return m_nuclearCharges.at(i); }
    const QList<qint64> nuclearChargesList() const { return m_nuclearCharges.toList(); }

    const qreal* xGaussianPrimitiveCenterCoordinates() const { return m_xGaussianPrimitiveCenterCoordinates.constData(); }
    const qreal* yGaussianPrimitiveCenterCoordinates() const { return m_yGaussianPrimitiveCenterCoordinates.constData(); }
    const qreal* zGaussianPrimitiveCenterCoordinates() const { return m_zGaussianPrimitiveCenterCoordinates.constData(); }
    qreal xGaussianPrimitiveCenterCoordinate( qint64 i ) const { return m_xGaussianPrimitiveCenterCoordinates.at(i); }
    qreal yGaussianPrimitiveCenterCoordinate( qint64 i ) const { return m_yGaussianPrimitiveCenterCoordinates.at(i); }
    qreal zGaussianPrimitiveCenterCoordinate( qint64 i ) const { return m_zGaussianPrimitiveCenterCoordinates.at(i); }

    const qint64* xGaussianPrimitiveAngularMomenta() const { return m_xGaussianPrimitiveAngularMomenta.constData(); }
    const qint64* yGaussianPrimitiveAngularMomenta() const { return m_yGaussianPrimitiveAngularMomenta.constData(); }
    const qint64* zGaussianPrimitiveAngularMomenta() const { return m_zGaussianPrimitiveAngularMomenta.constData(); }
    qint64 xGaussianPrimitiveAngularMomentum( qint64 i ) const { return m_xGaussianPrimitiveAngularMomenta.at(i); }
    qint64 yGaussianPrimitiveAngularMomentum( qint64 i ) const { return m_yGaussianPrimitiveAngularMomenta.at(i); }
    qint64 zGaussianPrimitiveAngularMomentum( qint64 i ) const { return m_zGaussianPrimitiveAngularMomenta.at(i); }

    const qreal* gaussianPrimitiveExponentCoefficients() const { return m_gaussianPrimitiveExponentCoefficients.constData(); }
    qreal gaussianPrimitiveExponentCoefficient( qint64 i ) const { return m_gaussianPrimitiveExponentCoefficients.at(i); }

    const qreal* molecularOrbitalOccupationNumbers() const { return m_molecularOrbitalOccupationNumbers.constData(); }
    qreal molecularOrbitalOccupationNumber( qint64 i ) const { return m_molecularOrbitalOccupationNumbers.at(i); }

    const qreal* molecularOrbitalEigenvalues() const { return m_molecularOrbitalEigenvalues.constData(); }
    qreal molecularOrbitalEigenvalue( qint64 i ) const { return m_molecularOrbitalEigenvalues.at(i); }

    const qreal* molecularOrbitalCoefficients() const { return m_molecularOrbitalCoefficients.constData(); }
    qreal molecularOrbitalCoefficient( qint64 i ) const { return m_molecularOrbitalCoefficients.at(i); }
    qreal molecularOrbitalCoefficient( qint64 mo, qint64 prim ) const { return m_molecularOrbitalCoefficients.at( mo*m_numberOfGaussianPrimitives + prim ); }

    qreal totalEnergy() const { return m_totalEnergy; }
    qreal virialRatio() const { return m_virialRatio; }

  private:

    bool m_initializationSuccessful;
    bool m_fileDoesNotExist;
    bool m_ioError;
    bool m_tooManyNuclei;
    bool m_maximumAngularMomentumExceeded;

    QString m_fileName;
    QString m_comment;

    qint64 m_numberOfMolecularOrbitals;
    qint64 m_numberOfGaussianPrimitives;
    qint64 m_numberOfNuclei;

    QVector<qreal> m_xNuclearCoordinates;
    QVector<qreal> m_yNuclearCoordinates;
    QVector<qreal> m_zNuclearCoordinates;

    QVector<qint64> m_nuclearCharges;

    QVector<qreal> m_xGaussianPrimitiveCenterCoordinates;
    QVector<qreal> m_yGaussianPrimitiveCenterCoordinates;
    QVector<qreal> m_zGaussianPrimitiveCenterCoordinates;

    QVector<qint64> m_xGaussianPrimitiveAngularMomenta;
    QVector<qint64> m_yGaussianPrimitiveAngularMomenta;
    QVector<qint64> m_zGaussianPrimitiveAngularMomenta;

    QVector<qreal> m_gaussianPrimitiveExponentCoefficients;

    QVector<qreal> m_molecularOrbitalOccupationNumbers;
    QVector<qreal> m_molecularOrbitalEigenvalues;
    QVector<qreal> m_molecularOrbitalCoefficients;

    qreal m_totalEnergy;
    qreal m_virialRatio;

  };

} // namespace Avogadro

#endif // QTAIMWAVEFUNCTION_H
