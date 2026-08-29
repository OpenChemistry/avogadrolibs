/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_DISPLACEMENTDIALOG_H
#define AVOGADRO_QTPLUGINS_DISPLACEMENTDIALOG_H

#include <QtWidgets/QDialog>

namespace Ui {
class DisplacementDialog;
}

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Asks how far to displace a geometry along one or more normal modes,
 * and how many structures to generate.
 */

class DisplacementDialog : public QDialog
{
  Q_OBJECT

public:
  explicit DisplacementDialog(QWidget* parent = nullptr,
                              Qt::WindowFlags f = Qt::WindowFlags());
  ~DisplacementDialog() override;

  /**
   * Show which modes the displacement will be built from, e.g.
   * "Mode 7 (1602.4 cm⁻¹)". Several modes are displaced together.
   */
  void setModeSummary(const QString& summary);

  /** @return The multiplier applied to the normal mode displacements. */
  double scaleFactor() const;

  /** @return How many structures to generate, at least one. */
  int structureCount() const;

private slots:
  /** Describe what the current scale and count will produce. */
  void updateSummary();

private:
  /** @return True when the scale factor would not displace anything. */
  bool isZeroScale() const;

  Ui::DisplacementDialog* m_ui;
};

} // End namespace QtPlugins
} // End namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_DISPLACEMENTDIALOG_H
