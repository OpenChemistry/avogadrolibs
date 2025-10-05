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

namespace QtPlugins {

enum class SpectraType
{
  Infrared,
  Raman,
  NMR,
  Electronic,
  CircularDichroism,
  DensityOfStates
};

class SpectraDialog : public QDialog
{
  Q_OBJECT

public:
  explicit SpectraDialog(QWidget* parent = 0);
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
  void changeImportedSpectraColor();
  void changeFontSize();
  void changeLineWidth();
  void changeSpectra();

  void exportData();

  void updateElementCombo();
  void updatePlot();

  void toggleOptions();

private:
  std::map<std::string, MatrixX> m_spectra;
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
