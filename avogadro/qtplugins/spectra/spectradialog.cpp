/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "spectradialog.h"

#include "ui_spectradialog.h"

#include <QtCore/QSettings>
#include <QtGui/QColor>
#include <QtGui/QScreen>
#include <QtWidgets/QColorDialog>

#include <QtCore/QDebug>

#include <avogadro/core/molecule.h>

#include <avogadro/vtk/chartwidget.h>

using namespace std;
using Avogadro::Core::Molecule;

namespace Avogadro::QtPlugins {

constexpr QColor black(0, 0, 0);
constexpr QColor white(1, 1, 1);
constexpr QColor red(1, 0, 0);
constexpr QColor green(0, 1, 0);
constexpr QColor blue(0, 0, 1);

float scaleAndBlur(float x, float peak, float intensity, float scale = 1.0,
                   float shift = 0.0, float fwhm = 0.0)
{
  // return the intensity at point x, from a Gaussian centered at peak
  // with a width of fwhm, scaled by scale and shifted by shift
  float fwhm_to_sigma = 2.0 * sqrt(2.0 * log(2.0));
  float sigma = fwhm / fwhm_to_sigma;

  // x is the absolute position, but we need to scale the peak position
  float scaled_peak = (peak - shift) / scale;
  float delta = x - scaled_peak;
  float exponent = -(delta * delta) / (2 * sigma * sigma);
  float gaussian = exp(exponent);
  return intensity * gaussian;
}

std::vector<double> fromMatrix(const MatrixX& matrix)
{
  std::vector<double> result;
  for (auto i = 0; i < matrix.rows(); ++i)
    result.push_back(matrix(i, 0));
  return result;
}

SpectraDialog::SpectraDialog(QWidget* parent)
  : QDialog(parent), m_ui(new Ui::SpectraDialog)
{
  m_ui->setupUi(this);
  m_ui->dataTable->horizontalHeader()->setSectionResizeMode(
    QHeaderView::Stretch);

  // Hide advanced options initially
  m_ui->tab_widget->hide();
  m_ui->dataTable->hide();
  m_ui->push_exportData->hide();

  // connections for options
  connect(m_ui->push_options, SIGNAL(clicked()), this, SLOT(toggleOptions()));
  connect(m_ui->push_colorBackground, SIGNAL(clicked()), this,
          SLOT(changeBackgroundColor()));
  connect(m_ui->push_colorForeground, SIGNAL(clicked()), this,
          SLOT(changeForegroundColor()));

  readSettings();
}

SpectraDialog::~SpectraDialog()
{
  writeSettings();
}

void SpectraDialog::setSpectra(const std::map<std::string, MatrixX>& spectra)
{
  m_spectra = spectra;

  // update the combo box
  m_ui->combo_spectra->clear();
  for (auto& spectra : m_spectra) {
    QString name = QString::fromStdString(spectra.first);
    if (name == "IR") {
      name = tr("Infrared");
      m_ui->combo_spectra->addItem(name,
                                   static_cast<int>(SpectraType::Infrared));
    } else if (name == "Raman") {
      name = tr("Raman");
      m_ui->combo_spectra->addItem(name, static_cast<int>(SpectraType::Raman));
    } else if (name == "NMR") {
      name = tr("NMR");
      m_ui->combo_spectra->addItem(name, static_cast<int>(SpectraType::NMR));
    } else if (name == "Electronic") {
      name = tr("Electronic");
      m_ui->combo_spectra->addItem(name,
                                   static_cast<int>(SpectraType::Electronic));
    } else if (name == "CircularDichroism") {
      name = tr("Circular Dichroism");
      m_ui->combo_spectra->addItem(
        name, static_cast<int>(SpectraType::CircularDichroism));
    } else if (name == "DensityOfStates") {
      name = tr("Density of States");
      m_ui->combo_spectra->addItem(
        name, static_cast<int>(SpectraType::DensityOfStates));
    }
  }

  updatePlot();
}

void SpectraDialog::writeSettings() const
{
  QSettings settings;

  settings.setValue("spectra/currentSpectra",
                    m_ui->combo_spectra->currentIndex());
}

void SpectraDialog::readSettings()
{
  QSettings settings;
  // update the dialog with the settings
}

void SpectraDialog::changeBackgroundColor()
{
  QSettings settings;
  QColor current =
    settings.value("spectra/backgroundColor", white).value<QColor>();
  QColor color =
    QColorDialog::getColor(current, this, tr("Select Background Color"));
  if (color.isValid() && color != current) {
    settings.setValue("spectra/backgroundColor", color);
    updatePlot();
  }
}

void SpectraDialog::changeForegroundColor()
{
  QSettings settings;
  QColor current =
    settings.value("spectra/foregroundColor", black).value<QColor>();
  QColor color =
    QColorDialog::getColor(current, this, tr("Select Foreground Color"));
  if (color.isValid() && color != current) {
    settings.setValue("spectra/foregroundColor", color);
    updatePlot();
  }
}

void SpectraDialog::changeCalculatedSpectraColor()
{
  QSettings settings;
  QColor current =
    settings.value("spectra/calculatedColor", black).value<QColor>();
  QColor color = QColorDialog::getColor(current, this,
                                        tr("Select Calculated Spectra Color"));
  if (color.isValid() && color != current) {
    settings.setValue("spectra/calculatedColor", color);
    updatePlot();
  }
}

void SpectraDialog::changeImportedSpectraColor()
{
  QSettings settings;
  QColor current = settings.value("spectra/importedColor", red).value<QColor>();
  QColor color =
    QColorDialog::getColor(current, this, tr("Select Imported Spectra Color"));
  if (color.isValid() && color != current) {
    settings.setValue("spectra/importedColor", color);
    updatePlot();
  }
}

void SpectraDialog::changeFontSize()
{
  int size = m_ui->fontSizeCombo->currentText().toInt();
  QSettings settings;
  settings.setValue("spectra/fontSize", size);
  updatePlot();
}

///////////////////////
// Plot Manipulation //
///////////////////////

void SpectraDialog::updatePlot()
{
  // the raw data
  std::vector<double> transitions, intensities;
  // for the plot
  std::vector<float> xData, yData, yStick;

  // determine the type to plot
  SpectraType type =
    static_cast<SpectraType>(m_ui->combo_spectra->currentData().toInt());

  QString windowName;
  QString xTitle;
  QString yTitle;
  // get the raw data from the spectra map
  switch (type) {
    case SpectraType::Infrared:
      transitions = fromMatrix(m_spectra["IR"].col(0));
      intensities = fromMatrix(m_spectra["IR"].col(1));
      windowName = tr("Vibrational Spectra");
      xTitle = tr("Wavenumbers (cm⁻¹)");
      yTitle = tr("Transmission");
      break;
    case SpectraType::Raman:
      transitions = fromMatrix(m_spectra["Raman"].col(0));
      intensities = fromMatrix(m_spectra["Raman"].col(1));
      windowName = tr("Raman Spectra");
      xTitle = tr("Wavenumbers (cm⁻¹)");
      yTitle = tr("Intensity");
      break;
    case SpectraType::NMR:
      transitions = fromMatrix(m_spectra["NMR"].col(0));
      intensities = fromMatrix(m_spectra["NMR"].col(1));
      windowName = tr("NMR Spectra");
      xTitle = tr("Chemical Shift (ppm)");
      yTitle = tr("Intensity");
      break;
    case SpectraType::Electronic:
      transitions = fromMatrix(m_spectra["Electronic"].col(0));
      intensities = fromMatrix(m_spectra["Electronic"].col(1));
      windowName = tr("Electronic Spectra");
      xTitle = tr("eV");
      yTitle = tr("Intensity");
      break;
    case SpectraType::CircularDichroism:
      transitions = fromMatrix(m_spectra["Electronic"].col(0));
      intensities = fromMatrix(m_spectra["Electronic"].col(2));
      windowName = tr("Circular Dichroism Spectra");
      xTitle = tr("eV)");
      yTitle = tr("Intensity");
      break;
    case SpectraType::DensityOfStates:
      transitions = fromMatrix(m_spectra["DensityOfStates"].col(0));
      intensities = fromMatrix(m_spectra["DensityOfStates"].col(1));
      windowName = tr("Density of States");
      xTitle = tr("eV");
      yTitle = tr("Intensity");
      break;
  }
  setWindowTitle(windowName);

  double maxIntensity = 0.0f;
  for (auto intensity : intensities) {
    if (intensity > maxIntensity)
      maxIntensity = intensity;
  }

  // now compose the plot data
  float scale = m_ui->scaleSpinBox->value();
  float offset = m_ui->offsetSpinBox->value();
  float fwhm = m_ui->peakWidth->value();

  // float xMin = m_ui->xAxisMinimum->value();
  // float xMax = m_ui->xAxisMaximum->value();

  float xMin = 4000.0;
  float xMax = 0.0;

  int start = std::min(static_cast<int>(xMin), static_cast<int>(xMax));
  int end = std::max(static_cast<int>(xMin), static_cast<int>(xMax));

  for (unsigned int x = start; x < end; ++x) {
    float xValue = static_cast<float>(x);
    xData.push_back(xValue);
    yData.push_back(0.0f);
    yStick.push_back(0.0f);

    // now we add up the intensity from any frequency
    for (auto index = 0; index < transitions.size(); ++index) {
      float freq = transitions[index];
      float peak = intensities[index];

      float intensity = scaleAndBlur(xValue, freq, peak, scale, offset, fwhm);
      float stick = scaleAndBlur(xValue, freq, peak, scale, offset, 0.0);

      yData.back() += intensity;
      yStick.back() += stick;
    }
  }

  auto* chart = chartWidget();
  chart->clearPlots();
  chart->setXAxisTitle(xTitle.toStdString());
  chart->setYAxisTitle(yTitle.toStdString());
  unsigned int fontSize = m_ui->fontSizeCombo->currentText().toInt();
  chart->setFontSize(fontSize);

  // get the spectra color
  QSettings settings;
  QColor spectraColor =
    settings.value("spectra/calculatedColor", black).value<QColor>();
  VTK::color4ub calculatedColor = {
    static_cast<unsigned char>(spectraColor.red()),
    static_cast<unsigned char>(spectraColor.green()),
    static_cast<unsigned char>(spectraColor.blue()),
    static_cast<unsigned char>(spectraColor.alpha())
  };
  chart->addPlot(xData, yData, calculatedColor);

  // axis limits
  /*/
  float xAxisMin = m_ui->xAxisMinimum->value();
  float xAxisMax = m_ui->xAxisMaximum->value();
  float yAxisMin = m_ui->yAxisMinimum->value();
  float yAxisMax = m_ui->yAxisMaximum->value();
  */
  float xAxisMin = 4000.0;
  float xAxisMax = 0.0;
  float yAxisMin = 0.0;
  float yAxisMax = maxIntensity * 1.1;

  chart->setXAxisLimits(xAxisMin, xAxisMax);
  chart->setYAxisLimits(yAxisMin, yAxisMax);
}

VTK::ChartWidget* SpectraDialog::chartWidget()
{
  return m_ui->plot;
}

void SpectraDialog::toggleOptions()
{
  if (m_ui->tab_widget->isHidden()) {
    m_ui->tab_widget->show();
    m_ui->dataTable->show();
    m_ui->push_exportData->show();
    QSize s = size();
    s.setWidth(s.width() + m_ui->dataTable->size().width());
    s.setHeight(s.height() + m_ui->tab_widget->size().height());
    QRect rect = QGuiApplication::primaryScreen()->geometry();
    if (s.width() > rect.width() || s.height() > rect.height())
      s = rect.size() * 0.9;
    resize(s);
    move(rect.width() / 2 - s.width() / 2, rect.height() / 2 - s.height() / 2);
  } else {
    QSize s = size();
    s.setWidth(s.width() - m_ui->dataTable->size().width());
    s.setHeight(s.height() - m_ui->tab_widget->size().height());
    resize(s);
    m_ui->tab_widget->hide();
    m_ui->dataTable->hide();
    m_ui->push_exportData->hide();
    QRect rect = QGuiApplication::primaryScreen()->geometry();
    move(rect.width() / 2 - s.width() / 2, rect.height() / 2 - s.height() / 2);
  }
}

} // namespace Avogadro::QtPlugins
