/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_ENERGYUNITSDIALOG_H
#define AVOGADRO_QTGUI_ENERGYUNITSDIALOG_H

#include "avogadroqtguiexport.h"

#include "energyunits.h"

#include <QtWidgets/QDialog>

class QComboBox;

namespace Avogadro {
namespace Core {
class Molecule;
}

namespace QtGui {

/**
 * @class EnergyUnitsDialog energyunitsdialog.h
 * <avogadro/qtgui/energyunitsdialog.h>
 * @brief Ask which units energies are in, and which to show them in.
 *
 * Reads as a sentence -- "Convert energies from Hartree to kcal/mol" -- and
 * on OK writes both to EnergyUnits, so everything showing an energy follows.
 */
class AVOGADROQTGUI_EXPORT EnergyUnitsDialog : public QDialog
{
  Q_OBJECT

public:
  /**
   * @param molecule the molecule whose energies are on screen, when there is
   * one. A file that records what units it used answers the first question
   * already, so that half of the dialog reports it rather than asking.
   */
  explicit EnergyUnitsDialog(QWidget* parent = nullptr,
                             const Core::Molecule* molecule = nullptr);
  ~EnergyUnitsDialog() override;

  /**
   * Show the dialog for @p parent and apply what the user chose.
   * @return true when they accepted it.
   */
  static bool getUnits(QWidget* parent = nullptr,
                       const Core::Molecule* molecule = nullptr);

  /** Write the chosen units to EnergyUnits. */
  void accept() override;

private:
  QComboBox* m_sourceCombo;
  QComboBox* m_displayCombo;
  // True when the molecule named its own units, in which case the source
  // combo is only reporting them and must not write them back.
  bool m_sourceDeclared = false;
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_ENERGYUNITSDIALOG_H
