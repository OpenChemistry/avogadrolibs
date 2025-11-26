/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SPECTRADIALOG_H
#define AVOGADRO_QTPLUGINS_SPECTRADIALOG_H

#include <QDialog>

#include <avogadro/core/matrix.h>
#include <avogadro/core/molecule.h>

namespace Ui {
class SpectraDialog;
}

namespace Avogadro {

namespace QtGui {
class ChartWidget;
}

/**
 * Construct the SpectraDialog and initialize UI state.
 * @param parent Parent widget, or nullptr.
 */

/**
 * Destroy the SpectraDialog and free associated resources.
 */

/**
 * Persist user-adjustable dialog settings (colors, sizes, last spectrum, etc.) to persistent storage.
 */

/**
 * Restore dialog settings previously saved by writeSettings().
 */

/**
 * Store available spectral datasets for plotting and selection.
 * @param spectra Map from spectrum name to its data matrix.
 */

/**
 * Update the set of atomic elements used (e.g., for NMR options) and refresh the element selection UI.
 * @param elements Vector of atomic numbers (as unsigned char) representing available elements.
 */

/**
 * Return the chart widget used to display spectra.
 * @returns Pointer to the ChartWidget instance used by the dialog.
 */

/**
 * Disconnect UI option signals to prevent them from triggering handlers (useful during programmatic updates).
 */

/**
 * Reconnect UI option signals after they have been disconnected.
 */

/**
 * Handle a mouse double-click event occurring on the dialog.
 * @param e The QMouseEvent describing the double-click.
 */

/**
 * Open a color chooser and apply the selected color to the chart background.
 */

/**
 * Open a color chooser and apply the selected color to chart foreground elements (axes, labels).
 */

/**
 * Open a color chooser and apply the selected color to calculated spectra traces.
 */

/**
 * Open a color chooser and apply the selected color to raw (original) spectra traces.
 */

/**
 * Open a color chooser and apply the selected color to imported spectra traces.
 */

/**
 * Update the font size used for chart text elements based on current UI options.
 */

/**
 * Update the line width used for plotted spectra based on current UI options.
 */

/**
 * Respond to a change in the selected spectrum type or dataset and update internal data accordingly.
 */

/**
 * Import spectral data from an external file and store it for plotting.
 */

/**
 * Export the currently displayed spectral data (calculated and/or imported) to a file.
 */

/**
 * Refresh the element selection control to reflect the current m_elements contents.
 */

/**
 * Rebuild and redraw the spectra plot using current transitions, intensities, colors, and import overlays.
 */

/**
 * Toggle visibility of the dialog's advanced options panel.
 */
namespace QtPlugins {

enum class SpectraType
{
  Infrared,
  Raman,
  NMR,
  Electronic,
  CircularDichroism,
  VibrationalCD,
  MagneticCD,
  DensityOfStates
};

class SpectraDialog : public QDialog
{
  Q_OBJECT

public:
  explicit SpectraDialog(QWidget* parent = nullptr);
  ~SpectraDialog() override;

  void writeSettings() const;
  void readSettings();

  void setSpectra(const std::map<std::string, MatrixX>& spectra);
  void setElements(const std::vector<unsigned char>& elements)
  {
    m_elements = elements;
    updateElementCombo();
  }

  QtGui::ChartWidget* chartWidget();

  void disconnectOptions();
  void connectOptions();

  void mouseDoubleClickEvent(QMouseEvent* e) override;

private slots:
  void changeBackgroundColor();
  void changeForegroundColor();
  void changeCalculatedSpectraColor();
  void changeRawSpectraColor();
  void changeImportedSpectraColor();
  void changeFontSize();
  void changeLineWidth();
  void changeSpectra();

  void importData();
  void exportData();

  void updateElementCombo();
  void updatePlot();

  void toggleOptions();

private:
  std::map<std::string, MatrixX> m_spectra;
  MatrixX m_importedSpectra;
  std::vector<unsigned char> m_elements; // for NMR
  // current spectra data
  std::vector<double> m_transitions;
  std::vector<double> m_intensities;
  // imported spectra (if available)
  std::vector<double> m_importedTransitions;
  std::vector<double> m_importedIntensities;

  QString m_currentSpectraType;
  Ui::SpectraDialog* m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif