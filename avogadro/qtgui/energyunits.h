/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_ENERGYUNITS_H
#define AVOGADRO_QTGUI_ENERGYUNITS_H

#include "avogadroqtguiexport.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QVector>

namespace Avogadro {
namespace Core {
class Molecule;
}

namespace QtGui {

/**
 * @class EnergyUnits energyunits.h <avogadro/qtgui/energyunits.h>
 * @brief The units energies are read in and shown in, shared application-wide.
 *
 * Energies arrive from a file in whatever unit the program that wrote them
 * used, and nothing in the file usually says which -- so the user has to.
 * Having said it once, they should not have to say it again in every window
 * showing the same numbers, which is what this is for: one setting, kept in
 * QSettings so it survives a restart, with a signal so that a conformer plot
 * and a conformer table open at the same time cannot disagree.
 *
 * @code
 * #include <avogadro/qtgui/energyunits.h>
 * ...
 * auto* units = EnergyUnits::instance();
 * connect(units, &EnergyUnits::unitsChanged, this, &MyView::refresh);
 * const double shown = units->convert(energyFromFile);
 * @endcode
 */
class AVOGADROQTGUI_EXPORT EnergyUnits : public QObject
{
  Q_OBJECT

public:
  /** @return the one instance, created on first use. */
  static EnergyUnits* instance();

  /**
   * The units an energy can be read in or shown in.
   *
   * The values are written to QSettings, so they are numbered explicitly:
   * inserting a unit in the middle must not change what an existing setting
   * means.
   */
  enum class Unit
  {
    Hartree = 0,
    ElectronVolt = 1,
    KcalPerMol = 2,
    KjPerMol = 3
  };
  Q_ENUM(Unit)

  /** @return every unit, in the order a combo box should list them. */
  static QVector<Unit> units();

  /**
   * @return the symbol for @p unit, such as "kcal/mol".
   *
   * Not translated: these are the symbols chemists write, and the same in
   * every locale.
   */
  static QString symbol(Unit unit);

  /**
   * @return the unit that @p symbol names, such as "kcal/mol".
   *
   * Spelling is taken loosely -- case is ignored, and the handful of names
   * the same unit goes by are accepted ("au" and "a.u." for Hartree, "kcal"
   * for kcal/mol) -- because the string may have come out of a file.
   * @param ok set to whether @p symbol named a unit at all; a name that is
   * not recognised must not be silently treated as the default.
   */
  static Unit fromSymbol(const QString& symbol, bool* ok = nullptr);

  /** @return the unit energies read from a file are taken to be in. */
  Unit sourceUnit() const { return m_sourceUnit; }

  /**
   * @return the unit @p molecule's energies are actually in: what the reader
   * recorded when it knew, and otherwise sourceUnit(), which is the user's to
   * say.
   *
   * A reader that knows what its program writes -- ORCA always writes
   * Hartree -- saves the user from having to say so, and must not be
   * overridden by a setting they last touched for some other file.
   */
  Unit sourceUnit(const Core::Molecule& molecule) const;

  /**
   * @return true when @p molecule's own energies name their unit, so nothing
   * needs asking. A dialog offering to set it should say so rather than
   * looking like it is being ignored.
   */
  static bool declaresUnit(const Core::Molecule& molecule);

  /** @return the unit energies are shown in. */
  Unit displayUnit() const { return m_displayUnit; }

  /** @return the symbol for the unit energies are shown in. */
  QString displaySymbol() const { return symbol(m_displayUnit); }

  /**
   * @return @p energy, read in sourceUnit(), expressed in displayUnit().
   *
   * Meant for an energy difference. Converting a total energy is arithmetic
   * all the same, but the answer is a number no one wants: total energies
   * differ by hundreds of Hartree between methods and mean nothing on their
   * own.
   */
  double convert(double energy) const;

  /** @return @p energy converted from @p from to @p to. */
  static double convert(double energy, Unit from, Unit to);

  /**
   * @return @p energy, read in @p molecule's own units, expressed in
   * displayUnit(). Prefer this wherever the molecule is at hand.
   */
  double convert(double energy, const Core::Molecule& molecule) const;

public slots:
  /**
   * Set the unit energies read from a file are taken to be in, saving it and
   * telling everything showing an energy to go and look again.
   */
  void setSourceUnit(Unit unit);

  /** Set the unit energies are shown in. */
  void setDisplayUnit(Unit unit);

  /** Set both at once, so that changing the pair emits one signal, not two. */
  void setUnits(Unit source, Unit display);

signals:
  /** Emitted when either unit changes. */
  void unitsChanged();

private:
  explicit EnergyUnits(QObject* parent = nullptr);

  Unit m_sourceUnit;
  Unit m_displayUnit;
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_ENERGYUNITS_H
