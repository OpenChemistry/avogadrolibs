/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/conformerquantity.h>
#include <avogadro/core/molecule.h>
#include <avogadro/qtgui/energyunits.h>

#include <QtCore/QCoreApplication>
#include <QtTest/QSignalSpy>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>

using Avogadro::QtGui::EnergyUnits;
using Unit = EnergyUnits::Unit;

TEST(EnergyUnitsTest, symbols)
{
  EXPECT_EQ(EnergyUnits::symbol(Unit::Hartree), QString("Hartree"));
  EXPECT_EQ(EnergyUnits::symbol(Unit::ElectronVolt), QString("eV"));
  EXPECT_EQ(EnergyUnits::symbol(Unit::KcalPerMol), QString("kcal/mol"));
  EXPECT_EQ(EnergyUnits::symbol(Unit::KjPerMol), QString("kJ/mol"));

  // Every unit has to be offered, or one of them could never be chosen.
  EXPECT_EQ(EnergyUnits::units().size(), 4);
}

TEST(EnergyUnitsTest, knownConversions)
{
  // CODATA: 1 Hartree = 627.5094740631 kcal/mol = 27.211386245988 eV.
  EXPECT_NEAR(EnergyUnits::convert(1.0, Unit::Hartree, Unit::KcalPerMol),
              627.5094740631, 1e-9);
  EXPECT_NEAR(EnergyUnits::convert(1.0, Unit::Hartree, Unit::ElectronVolt),
              27.211386245988, 1e-6);

  // The kilocalorie is 4.184 kJ by definition.
  EXPECT_NEAR(EnergyUnits::convert(1.0, Unit::KcalPerMol, Unit::KjPerMol),
              4.184, 1e-12);

  // 1 eV = 96.48533212 kJ/mol.
  EXPECT_NEAR(EnergyUnits::convert(1.0, Unit::ElectronVolt, Unit::KjPerMol),
              96.48533212, 1e-6);
}

TEST(EnergyUnitsTest, conversionRoundTrips)
{
  for (Unit from : EnergyUnits::units()) {
    for (Unit to : EnergyUnits::units()) {
      const double there = EnergyUnits::convert(2.5, from, to);
      const double back = EnergyUnits::convert(there, to, from);
      EXPECT_NEAR(back, 2.5, 1e-9)
        << EnergyUnits::symbol(from).toStdString() << " -> "
        << EnergyUnits::symbol(to).toStdString();
    }
  }

  // Converting to the same unit must be exact, not merely close: a table of
  // Hartree energies should read back the digits it was given.
  EXPECT_EQ(EnergyUnits::convert(1.2345, Unit::Hartree, Unit::Hartree), 1.2345);
}

// The whole point of the singleton is that a plot and a table both follow it,
// so a change has to be announced.
TEST(EnergyUnitsTest, changingUnitsEmitsOnce)
{
  auto* units = EnergyUnits::instance();
  units->setUnits(Unit::Hartree, Unit::KcalPerMol);

  QSignalSpy spy(units, &EnergyUnits::unitsChanged);
  ASSERT_TRUE(spy.isValid());

  // Both at once is one change, not two.
  units->setUnits(Unit::ElectronVolt, Unit::KjPerMol);
  EXPECT_EQ(spy.count(), 1);
  EXPECT_EQ(units->sourceUnit(), Unit::ElectronVolt);
  EXPECT_EQ(units->displayUnit(), Unit::KjPerMol);
  EXPECT_EQ(units->displaySymbol(), QString("kJ/mol"));

  // Setting what is already set announces nothing: it would put every table
  // showing an energy through a needless redraw.
  units->setUnits(Unit::ElectronVolt, Unit::KjPerMol);
  EXPECT_EQ(spy.count(), 1);

  units->setDisplayUnit(Unit::Hartree);
  EXPECT_EQ(spy.count(), 2);
  EXPECT_EQ(units->sourceUnit(), Unit::ElectronVolt);
  EXPECT_EQ(units->displayUnit(), Unit::Hartree);
}

TEST(EnergyUnitsTest, instanceConvertsWithTheCurrentPair)
{
  auto* units = EnergyUnits::instance();
  units->setUnits(Unit::Hartree, Unit::KcalPerMol);
  EXPECT_NEAR(units->convert(1.0), 627.5094740631, 1e-9);

  units->setUnits(Unit::KcalPerMol, Unit::KjPerMol);
  EXPECT_NEAR(units->convert(1.0), 4.184, 1e-12);
}

TEST(EnergyUnitsTest, symbolsParseBack)
{
  // Whatever symbol() writes, fromSymbol() has to read.
  for (Unit unit : EnergyUnits::units()) {
    bool ok = false;
    EXPECT_EQ(EnergyUnits::fromSymbol(EnergyUnits::symbol(unit), &ok), unit);
    EXPECT_TRUE(ok);
  }

  // Strings out of a file were written for a person, so case and the other
  // names a unit goes by are taken as they come.
  bool ok = false;
  EXPECT_EQ(EnergyUnits::fromSymbol("hartree", &ok), Unit::Hartree);
  EXPECT_TRUE(ok);
  EXPECT_EQ(EnergyUnits::fromSymbol("  a.u. ", &ok), Unit::Hartree);
  EXPECT_TRUE(ok);
  EXPECT_EQ(EnergyUnits::fromSymbol("KCAL/MOL", &ok), Unit::KcalPerMol);
  EXPECT_TRUE(ok);
  EXPECT_EQ(EnergyUnits::fromSymbol("kJ/mol", &ok), Unit::KjPerMol);
  EXPECT_TRUE(ok);
}

// An unrecognised unit must say so rather than passing for the default: a
// silent fall back to Hartree would scale a kcal/mol energy by 627.
TEST(EnergyUnitsTest, unknownSymbolIsReported)
{
  bool ok = true;
  EnergyUnits::fromSymbol("furlongs per fortnight", &ok);
  EXPECT_FALSE(ok);

  ok = true;
  EnergyUnits::fromSymbol("", &ok);
  EXPECT_FALSE(ok);
}

// A reader that knows what its program writes has already answered the
// question, and must not be overridden by a setting left over from some other
// file the user opened.
TEST(EnergyUnitsTest, moleculeUnitBeatsTheSetting)
{
  auto* units = EnergyUnits::instance();
  units->setUnits(Unit::KcalPerMol, Unit::KjPerMol);

  Avogadro::Core::Molecule molecule;
  EXPECT_FALSE(EnergyUnits::declaresUnit(molecule));
  // Nothing recorded, so the user's setting is all there is.
  EXPECT_EQ(units->sourceUnit(molecule), Unit::KcalPerMol);
  EXPECT_NEAR(units->convert(1.0, molecule), 4.184, 1e-12);

  // ORCA always writes Hartree, and says so.
  Avogadro::Core::setEnergyUnit(molecule, "Hartree");
  EXPECT_TRUE(EnergyUnits::declaresUnit(molecule));
  EXPECT_EQ(units->sourceUnit(molecule), Unit::Hartree);
  EXPECT_NEAR(units->convert(1.0, molecule), 627.5094740631 * 4.184, 1e-6);

  // The user's own setting is untouched by any of that.
  EXPECT_EQ(units->sourceUnit(), Unit::KcalPerMol);
}

TEST(EnergyUnitsTest, unrecognisedMoleculeUnitFallsBackToTheSetting)
{
  auto* units = EnergyUnits::instance();
  units->setUnits(Unit::ElectronVolt, Unit::KcalPerMol);

  Avogadro::Core::Molecule molecule;
  Avogadro::Core::setEnergyUnit(molecule, "rydberg");

  // Recorded, but as nothing this knows how to convert: better to ask the
  // user than to convert by a factor picked at random.
  EXPECT_FALSE(EnergyUnits::declaresUnit(molecule));
  EXPECT_EQ(units->sourceUnit(molecule), Unit::ElectronVolt);
}

// Energies that replace a file's own must replace its recorded unit too. The
// force-field plugin stamps kJ/mol when it writes them; this is the arithmetic
// that makes that matter, and the failure it prevents.
TEST(EnergyUnitsTest, replacedEnergiesMustNotKeepTheOldUnit)
{
  auto* units = EnergyUnits::instance();
  units->setUnits(Unit::Hartree, Unit::KcalPerMol);

  // Read from ORCA: Hartree, and recorded as such.
  Avogadro::Core::Molecule molecule;
  Avogadro::Core::setEnergyUnit(molecule, "Hartree");

  // A force-field run replaces the energies with its own, in kJ/mol. One
  // kJ/mol is 0.239 kcal/mol; read as Hartree it would come out at 150.
  const double kjPerMolEnergy = 1.0;
  EXPECT_NEAR(units->convert(kjPerMolEnergy, molecule), 627.5094740631, 1e-6);

  Avogadro::Core::setEnergyUnit(molecule, "kJ/mol");
  EXPECT_NEAR(units->convert(kjPerMolEnergy, molecule), 1.0 / 4.184, 1e-9);
}

// Open Babel's conformer search hands back energies without saying what they
// are in. Recording that nobody knows is what puts the question back to the
// user, rather than leaving the previous file's answer standing.
TEST(EnergyUnitsTest, clearingTheUnitReturnsToTheSetting)
{
  auto* units = EnergyUnits::instance();
  units->setUnits(Unit::KcalPerMol, Unit::KjPerMol);

  Avogadro::Core::Molecule molecule;
  Avogadro::Core::setEnergyUnit(molecule, "Hartree");
  ASSERT_TRUE(EnergyUnits::declaresUnit(molecule));

  Avogadro::Core::setEnergyUnit(molecule, std::string());
  EXPECT_FALSE(EnergyUnits::declaresUnit(molecule));
  EXPECT_EQ(units->sourceUnit(molecule), Unit::KcalPerMol);
}

// The plot and the dialog both fill a combo from scratch, and both rely on
// the current selection landing on the unit that was already in force.
TEST(EnergyUnitsTest, fillComboListsEveryUnitAndSelectsCurrent)
{
  QComboBox combo;
  EnergyUnits::fillCombo(&combo, Unit::KcalPerMol);

  ASSERT_EQ(combo.count(), EnergyUnits::units().size());
  for (int i = 0; i < combo.count(); ++i) {
    bool ok = false;
    const int stored = combo.itemData(i).toInt(&ok);
    ASSERT_TRUE(ok);
    EXPECT_EQ(stored, static_cast<int>(EnergyUnits::units().at(i)));
    EXPECT_EQ(combo.itemText(i),
              EnergyUnits::symbol(EnergyUnits::units().at(i)));
  }
  EXPECT_EQ(combo.currentData().toInt(), static_cast<int>(Unit::KcalPerMol));
}

// The molecule combo box is refilled whenever a new file changes what its
// source unit is, so a second call has to start clean rather than growing.
TEST(EnergyUnitsTest, fillComboReplacesExistingItems)
{
  QComboBox combo;
  combo.addItem("stale", 12345);
  EnergyUnits::fillCombo(&combo, Unit::Hartree);

  EXPECT_EQ(combo.count(), EnergyUnits::units().size());
  for (int i = 0; i < combo.count(); ++i)
    EXPECT_NE(combo.itemText(i), QString("stale"));
}

// A caller connects to currentIndexChanged only after filling the combo
// itself; if filling it announced a change, that connection would see a
// spurious signal for a selection the user never made.
TEST(EnergyUnitsTest, fillComboDoesNotEmitCurrentIndexChanged)
{
  QComboBox combo;
  combo.addItem("stale", 12345);

  int emitted = 0;
  QObject::connect(&combo, QOverload<int>::of(&QComboBox::currentIndexChanged),
                   [&emitted]() { ++emitted; });

  EnergyUnits::fillCombo(&combo, Unit::ElectronVolt);
  EXPECT_EQ(emitted, 0);
}

TEST(EnergyUnitsTest, unitFromComboRoundTripsEveryUnit)
{
  QComboBox combo;
  for (Unit unit : EnergyUnits::units()) {
    EnergyUnits::fillCombo(&combo, unit);
    EXPECT_EQ(EnergyUnits::unitFromCombo(&combo, Unit::Hartree), unit);
  }
}

// An empty combo, an item whose data names nothing this recognises, and a
// null pointer are all the same case to the caller: nothing usable to read,
// so the fallback stands rather than the code guessing or crashing.
TEST(EnergyUnitsTest, unitFromComboFallsBackWhenNothingUsableIsSelected)
{
  QComboBox empty;
  EXPECT_EQ(EnergyUnits::unitFromCombo(&empty, Unit::KjPerMol), Unit::KjPerMol);

  QComboBox unknown;
  unknown.addItem("nonsense", 99);
  EXPECT_EQ(EnergyUnits::unitFromCombo(&unknown, Unit::ElectronVolt),
            Unit::ElectronVolt);

  EXPECT_EQ(EnergyUnits::unitFromCombo(nullptr, Unit::Hartree), Unit::Hartree);
}

// fillCombo() must survive being asked to fill nothing: a caller that has not
// yet built its widget must not crash the whole dialog.
TEST(EnergyUnitsTest, fillComboToleratesNullCombo)
{
  EnergyUnits::fillCombo(nullptr, Unit::Hartree);
}
