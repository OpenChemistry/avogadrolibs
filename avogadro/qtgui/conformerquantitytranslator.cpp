/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "conformerquantitytranslator.h"

#include <avogadro/core/conformerquantity.h>

namespace Avogadro::QtGui {

using Core::ConformerQuantity;

ConformerQuantityTranslator::ConformerQuantityTranslator() : QObject() {}

QString ConformerQuantityTranslator::name(const ConformerQuantity& quantity)
{
  using Type = ConformerQuantity::Type;

  if (quantity.type() == Type::Coordinate) {
    // Atom numbers count from one here, matching the constraints dialog and
    // the property tables rather than the indices underneath.
    const Core::Constraint& c = quantity.coordinate();
    const auto number = [](Index index) {
      return QString::number(static_cast<qulonglong>(index) + 1);
    };

    switch (c.type()) {
      case Core::Constraint::DistanceConstraint:
        return tr("Distance %1-%2").arg(number(c.aIndex()), number(c.bIndex()));
      case Core::Constraint::AngleConstraint:
        return tr("Angle %1-%2-%3")
          .arg(number(c.aIndex()), number(c.bIndex()), number(c.cIndex()));
      case Core::Constraint::TorsionConstraint:
        return tr("Dihedral %1-%2-%3-%4")
          .arg(number(c.aIndex()), number(c.bIndex()), number(c.cIndex()),
               number(c.dIndex()));
      default:
        return tr("Constraint");
    }
  }

  switch (quantity.type()) {
    case Type::Frame:
      return tr("Frame", "position in a trajectory, counting from one");
    case Type::Time:
      return tr("Time");
    case Type::Rmsd:
      return tr("RMSD", "root mean square displacement");
    case Type::Energy:
      return tr("Relative Energy");
    case Type::Forces:
      return tr("RMS Gradient");
    case Type::MeanSpeed:
      return tr("Mean Speed", "average over the atoms of how fast each moves");
    case Type::Temperature:
      return tr("Temperature");
    case Type::Coordinate:
      break; // handled above
  }

  return QString();
}

QString ConformerQuantityTranslator::label(const ConformerQuantity& quantity,
                                           const QString& unit)
{
  const QString quantityName = name(quantity);

  // A unit the caller converted to wins over the one the values arrived in:
  // only the caller knows it picked kJ/mol over the file's Hartree.
  QString symbol = unit;
  if (symbol.isEmpty())
    symbol = QString::fromStdString(quantity.unit());
  if (symbol.isEmpty())
    return quantityName;

  return tr("%1 (%2)", "quantity name, then its unit")
    .arg(quantityName, symbol);
}

} // namespace Avogadro::QtGui
