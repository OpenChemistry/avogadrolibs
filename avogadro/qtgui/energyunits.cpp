/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "energyunits.h"

#include <avogadro/core/conformerquantity.h>
#include <avogadro/core/molecule.h>

#include <QtCore/QSettings>

namespace Avogadro::QtGui {

namespace {

// Everything converts through kcal/mol rather than by a table of every pair.
// 1 Hartree = 627.5094740631 kcal/mol (CODATA); 1 eV = 96.48533212 kJ/mol over
// 4.184 kJ/kcal; the kilocalorie is 4.184 kJ by definition.
constexpr double HartreeToKcal = 627.5094740631;
constexpr double ElectronVoltToKcal = 23.060547830619026;
constexpr double KjToKcal = 1.0 / 4.184;

const char* const SourceUnitKey = "energy/sourceUnit";
const char* const DisplayUnitKey = "energy/displayUnit";

double toKcalPerMol(EnergyUnits::Unit unit)
{
  switch (unit) {
    case EnergyUnits::Unit::Hartree:
      return HartreeToKcal;
    case EnergyUnits::Unit::ElectronVolt:
      return ElectronVoltToKcal;
    case EnergyUnits::Unit::KjPerMol:
      return KjToKcal;
    case EnergyUnits::Unit::KcalPerMol:
      break;
  }
  return 1.0;
}

// A value read back from QSettings is whatever was in the file, so check it
// names a unit rather than trusting it into the enum.
EnergyUnits::Unit readUnit(const QSettings& settings, const char* key,
                           EnergyUnits::Unit fallback)
{
  bool ok = false;
  const int stored = settings.value(key, -1).toInt(&ok);
  if (!ok)
    return fallback;

  for (EnergyUnits::Unit unit : EnergyUnits::units()) {
    if (static_cast<int>(unit) == stored)
      return unit;
  }
  return fallback;
}

} // namespace

EnergyUnits::EnergyUnits(QObject* parent) : QObject(parent)
{
  QSettings settings;
  // Hartree in, kcal/mol out: quantum chemistry writes the one and chemists
  // talk in the other, so it is the pair most users would pick anyway.
  m_sourceUnit = readUnit(settings, SourceUnitKey, Unit::Hartree);
  m_displayUnit = readUnit(settings, DisplayUnitKey, Unit::KcalPerMol);
}

EnergyUnits* EnergyUnits::instance()
{
  static EnergyUnits theInstance;
  return &theInstance;
}

QVector<EnergyUnits::Unit> EnergyUnits::units()
{
  return { Unit::Hartree, Unit::ElectronVolt, Unit::KcalPerMol,
           Unit::KjPerMol };
}

QString EnergyUnits::symbol(Unit unit)
{
  switch (unit) {
    case Unit::Hartree:
      return QStringLiteral("Hartree");
    case Unit::ElectronVolt:
      return QStringLiteral("eV");
    case Unit::KcalPerMol:
      return QStringLiteral("kcal/mol");
    case Unit::KjPerMol:
      return QStringLiteral("kJ/mol");
  }
  return QString();
}

EnergyUnits::Unit EnergyUnits::fromSymbol(const QString& symbol, bool* ok)
{
  if (ok != nullptr)
    *ok = true;

  const QString name = symbol.trimmed().toLower();

  // The symbols above first, then the other names the same units go by: a
  // string that came out of a file was written for a person to read, not for
  // this to parse.
  for (Unit unit : units()) {
    if (name == EnergyUnits::symbol(unit).toLower())
      return unit;
  }

  if (name == QLatin1String("au") || name == QLatin1String("a.u.") ||
      name == QLatin1String("atomic units") || name == QLatin1String("eh") ||
      name == QLatin1String("hartrees"))
    return Unit::Hartree;
  if (name == QLatin1String("ev") || name == QLatin1String("electronvolt") ||
      name == QLatin1String("electron volts"))
    return Unit::ElectronVolt;
  if (name == QLatin1String("kcal") || name == QLatin1String("kcal mol^-1") ||
      name == QLatin1String("kcal/mole"))
    return Unit::KcalPerMol;
  if (name == QLatin1String("kj") || name == QLatin1String("kj mol^-1") ||
      name == QLatin1String("kj/mole"))
    return Unit::KjPerMol;

  // Not a unit anyone here knows. Saying so matters: treating it as the
  // default would convert by a factor of 627 without anyone noticing.
  if (ok != nullptr)
    *ok = false;
  return Unit::Hartree;
}

bool EnergyUnits::declaresUnit(const Core::Molecule& molecule)
{
  const std::string recorded = Core::energyUnit(molecule);
  if (recorded.empty())
    return false;

  bool ok = false;
  fromSymbol(QString::fromStdString(recorded), &ok);
  return ok;
}

EnergyUnits::Unit EnergyUnits::sourceUnit(const Core::Molecule& molecule) const
{
  const std::string recorded = Core::energyUnit(molecule);
  if (!recorded.empty()) {
    bool ok = false;
    const Unit unit = fromSymbol(QString::fromStdString(recorded), &ok);
    if (ok)
      return unit;
  }

  // Nothing recorded, or recorded as something unrecognised: the user's
  // setting is all there is to go on.
  return m_sourceUnit;
}

double EnergyUnits::convert(double energy, const Core::Molecule& molecule) const
{
  return convert(energy, sourceUnit(molecule), m_displayUnit);
}

double EnergyUnits::convert(double energy, Unit from, Unit to)
{
  if (from == to)
    return energy;
  return energy * toKcalPerMol(from) / toKcalPerMol(to);
}

double EnergyUnits::convert(double energy) const
{
  return convert(energy, m_sourceUnit, m_displayUnit);
}

void EnergyUnits::setSourceUnit(Unit unit)
{
  setUnits(unit, m_displayUnit);
}

void EnergyUnits::setDisplayUnit(Unit unit)
{
  setUnits(m_sourceUnit, unit);
}

void EnergyUnits::setUnits(Unit source, Unit display)
{
  if (source == m_sourceUnit && display == m_displayUnit)
    return;

  m_sourceUnit = source;
  m_displayUnit = display;

  QSettings settings;
  settings.setValue(SourceUnitKey, static_cast<int>(source));
  settings.setValue(DisplayUnitKey, static_cast<int>(display));

  emit unitsChanged();
}

} // namespace Avogadro::QtGui
