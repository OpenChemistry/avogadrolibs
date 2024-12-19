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

  // hide the units for now
  m_ui->unitsLabel->hide();
  m_ui->unitsCombo->hide();

  // only for NMR
  m_ui->elementCombo->hide();

  m_ui->dataTable->horizontalHeader()->setSectionResizeMode(
    QHeaderView::Stretch);

  // Hide advanced options initially
  m_ui->tab_widget->hide();
  m_ui->dataTable->hide();
  m_ui->push_exportData->hide();

  readSettings();

  // connections for options
  connect(m_ui->push_options, SIGNAL(clicked()), this, SLOT(toggleOptions()));
  connect(m_ui->push_colorBackground, SIGNAL(clicked()), this,
          SLOT(changeBackgroundColor()));
  connect(m_ui->push_colorForeground, SIGNAL(clicked()), this,
          SLOT(changeForegroundColor()));
  connect(m_ui->push_colorCalculated, SIGNAL(clicked()), this,
          SLOT(changeCalculatedSpectraColor()));
  connect(m_ui->push_colorImported, SIGNAL(clicked()), this,
          SLOT(changeImportedSpectraColor()));
  connect(m_ui->fontSizeCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(changeFontSize()));
  connect(m_ui->lineWidthSpinBox, SIGNAL(valueChanged(double)), this,
          SLOT(changeLineWidth()));
  connectOptions();
}

SpectraDialog::~SpectraDialog()
{
  writeSettings();
}

void SpectraDialog::connectOptions()
{
  // connect (or reconnect) anything that calls change or update plot
  connect(m_ui->combo_spectra, SIGNAL(currentIndexChanged(int)), this,
          SLOT(changeSpectra()));
  connect(m_ui->xAxisMinimum, SIGNAL(valueChanged(double)), this,
          SLOT(updatePlot()));
  connect(m_ui->xAxisMaximum, SIGNAL(valueChanged(double)), this,
          SLOT(updatePlot()));
  connect(m_ui->yAxisMinimum, SIGNAL(valueChanged(double)), this,
          SLOT(updatePlot()));
  connect(m_ui->yAxisMaximum, SIGNAL(valueChanged(double)), this,
          SLOT(updatePlot()));
  connect(m_ui->peakWidth, SIGNAL(valueChanged(double)), this,
          SLOT(updatePlot()));
}

void SpectraDialog::disconnectOptions()
{
  // disconnect anything that calls change or update plot
  disconnect(m_ui->combo_spectra, SIGNAL(currentIndexChanged(int)), this,
             SLOT(changeSpectra()));
  disconnect(m_ui->xAxisMinimum, SIGNAL(valueChanged(double)), this,
             SLOT(updatePlot()));
  disconnect(m_ui->xAxisMaximum, SIGNAL(valueChanged(double)), this,
             SLOT(updatePlot()));
  disconnect(m_ui->yAxisMinimum, SIGNAL(valueChanged(double)), this,
             SLOT(updatePlot()));
  disconnect(m_ui->yAxisMaximum, SIGNAL(valueChanged(double)), this,
             SLOT(updatePlot()));
  disconnect(m_ui->peakWidth, SIGNAL(valueChanged(double)), this,
             SLOT(updatePlot()));
}

void SpectraDialog::updateElementCombo()
{
  // update the element combo box
  disconnect(m_ui->elementCombo, SIGNAL(currentIndexChanged(int)), this,
             SLOT(changeSpectra()));
  m_ui->elementCombo->clear();

  // add the unique elements, with the element number as the data
  for (auto& element : m_elements) {
    // check to see if it's already in the combo box
    bool found = false;
    for (int i = 0; i < m_ui->elementCombo->count(); ++i) {
      if (m_ui->elementCombo->itemData(i).toInt() == element) {
        found = true;
        break;
      }
    }
    if (found)
      continue;

    switch (element) {
      case 1:
        m_ui->elementCombo->addItem("¹H", element);
        break;
      case 3:
        m_ui->elementCombo->addItem("⁷Li", element);
        break;
      case 5:
        m_ui->elementCombo->addItem("¹¹B", element);
        break;
      case 6:
        m_ui->elementCombo->addItem("¹³C", element);
        break;
      case 7:
        m_ui->elementCombo->addItem("¹⁵N", element);
        break;
      case 8:
        m_ui->elementCombo->addItem("¹⁷O", element);
        break;
      case 9:
        m_ui->elementCombo->addItem("¹⁹F", element);
        break;
      case 14:
        m_ui->elementCombo->addItem("²⁹Si", element);
        break;
      case 15:
        m_ui->elementCombo->addItem("³¹P", element);
        break;
      default:
        m_ui->elementCombo->addItem(QString::number(element), element);
        break;
    }
  }

  // connect the element combo box
  connect(m_ui->elementCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(changeSpectra()));
}

void SpectraDialog::changeSpectra()
{
  // TODO: change the scale and offset based on defaults and settings
  QSettings settings;

  disconnectOptions();

  // what type of spectra are we plotting?
  SpectraType type =
    static_cast<SpectraType>(m_ui->combo_spectra->currentData().toInt());

  m_ui->elementCombo->hide();

  switch (type) {
    case SpectraType::Infrared:
      m_ui->scaleSpinBox->setValue(1.0);
      m_ui->offsetSpinBox->setValue(0.0);
      m_ui->xAxisMinimum->setValue(4000.0);
      m_ui->xAxisMaximum->setValue(0.0);
      m_ui->peakWidth->setValue(30.0);
      break;
    case SpectraType::Raman:
      m_ui->scaleSpinBox->setValue(1.0);
      m_ui->offsetSpinBox->setValue(0.0);
      m_ui->xAxisMinimum->setValue(0.0);
      m_ui->xAxisMaximum->setValue(4000.0);
      m_ui->peakWidth->setValue(30.0);
      break;
    case SpectraType::NMR:
      m_ui->scaleSpinBox->setValue(1.0);
      m_ui->offsetSpinBox->setValue(0.0);
      // todo: these should be per element
      m_ui->peakWidth->setValue(0.1);
      m_ui->elementCombo->show();
      break;
    case SpectraType::Electronic:
      m_ui->scaleSpinBox->setValue(1.0);
      m_ui->offsetSpinBox->setValue(0.0);
      // in eV
      m_ui->xAxisMinimum->setValue(5.0);
      m_ui->xAxisMaximum->setValue(1.0);
      m_ui->peakWidth->setValue(0.1);
      break;
    case SpectraType::CircularDichroism:
      m_ui->scaleSpinBox->setValue(1.0);
      m_ui->offsetSpinBox->setValue(0.0);
      // default to eV
      m_ui->xAxisMinimum->setValue(5.0);
      m_ui->xAxisMaximum->setValue(1.0);
      m_ui->peakWidth->setValue(0.1);
      break;
    case SpectraType::DensityOfStates:
      m_ui->scaleSpinBox->setValue(1.0);
      m_ui->offsetSpinBox->setValue(0.0);
      m_ui->xAxisMinimum->setValue(-50.0);
      m_ui->xAxisMaximum->setValue(50.0);
      m_ui->peakWidth->setValue(0.1);
      break;
  }

  // a bunch of special work depending on the NMR element
  if (type == SpectraType::NMR) {
    // get the element
    int element = m_ui->elementCombo->currentData().toInt();

    qDebug() << " NMR element: " << element;

    // tweak the default axis range
    // based on https://imserc.northwestern.edu/guide/eNMR/chem/NMRnuclei.html
    switch (element) {
      case 1: // 1H
        m_ui->xAxisMinimum->setValue(12.0);
        m_ui->xAxisMaximum->setValue(0.0);
        break;
      case 3: // 7Li
        m_ui->xAxisMinimum->setValue(-16.0);
        m_ui->xAxisMaximum->setValue(11.0);
        break;
      case 5: // 11B
        m_ui->xAxisMinimum->setValue(100.0);
        m_ui->xAxisMaximum->setValue(-120.0);
        break;
      case 6: // 13C
        m_ui->xAxisMinimum->setValue(200.0);
        m_ui->xAxisMaximum->setValue(0.0);
        break;
      case 7: // 15N
        m_ui->xAxisMinimum->setValue(800.0);
        m_ui->xAxisMaximum->setValue(0.0);
        break;
      case 8: // 17O
        m_ui->xAxisMinimum->setValue(1600.0);
        m_ui->xAxisMaximum->setValue(-50.0);
        break;
      case 9: // 19F
        m_ui->xAxisMinimum->setValue(60.0);
        m_ui->xAxisMaximum->setValue(-300.0);
        break;
      case 14: // 29Si
        m_ui->xAxisMinimum->setValue(50.0);
        m_ui->xAxisMaximum->setValue(-200.0);
        break;
      case 15: // 31P
        m_ui->xAxisMinimum->setValue(250.0);
        m_ui->xAxisMaximum->setValue(-250.0);
        break;
      default:
        m_ui->xAxisMinimum->setValue(100.0);
        m_ui->xAxisMaximum->setValue(-100.0);
        break;
    }

    // the default NMR data has all the atoms in it,
    // so we need to loop through m_elements to filter
    MatrixX nmr = m_spectra["NMR"];

    qDebug() << " NMR size: " << nmr.rows() << "x" << nmr.cols();
    qDebug() << " m_elements size: " << m_elements.size();

    std::vector<double> nmrPeaks;
    for (int i = 0; i < m_elements.size(); ++i) {
      if (m_elements[i] == element) {
        nmrPeaks[i] = nmr(i, 0);
      }
    }
    MatrixX newNMR(nmrPeaks.size(), 2);
    for (int i = 0; i < nmrPeaks.size(); ++i) {
      newNMR(i, 0) = nmrPeaks[i];
      newNMR(i, 1) = 1.0;
    }

    m_currentSpectra = newNMR;
  } else {
    m_currentSpectra =
      m_spectra[m_ui->combo_spectra->currentText().toStdString()];
  }

  updatePlot();
  connectOptions();
}

void SpectraDialog::setSpectra(const std::map<std::string, MatrixX>& spectra)
{
  m_spectra = spectra;

  // update the combo box
  disconnect(m_ui->combo_spectra, SIGNAL(currentIndexChanged(int)), this,
             SLOT(changeSpectra()));

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

  changeSpectra();
  // connect again
  connect(m_ui->combo_spectra, SIGNAL(currentIndexChanged(int)), this,
          SLOT(changeSpectra()));
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
  // update the dialog with saved settings

  // font size
  int fontSize = settings.value("spectra/fontSize", 12).toInt();
  m_ui->fontSizeCombo->setCurrentText(QString::number(fontSize));
  // line width
  float lineWidth = settings.value("spectra/lineWidth", 1.0).toFloat();
  m_ui->lineWidthSpinBox->setValue(lineWidth);
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

void SpectraDialog::changeLineWidth()
{
  float width = m_ui->lineWidthSpinBox->value();
  QSettings settings;
  settings.setValue("spectra/lineWidth", width);
  updatePlot();
}

///////////////////////
// Plot Manipulation //
///////////////////////

void SpectraDialog::updatePlot()
{
  // disconnect the options while we update the plot
  disconnectOptions();

  // the raw data
  std::vector<double> transitions, intensities;
  // for the plot
  std::vector<float> xData, yData, yStick;

  // determine the type to plot
  SpectraType type =
    static_cast<SpectraType>(m_ui->combo_spectra->currentData().toInt());

  QSettings settings;
  QString windowName;
  QString xTitle;
  QString yTitle;
  bool transmission = false;
  // get the raw data from the spectra map
  switch (type) {
    case SpectraType::Infrared:
      transitions = fromMatrix(m_spectra["IR"].col(0));
      intensities = fromMatrix(m_spectra["IR"].col(1));
      windowName = tr("Vibrational Spectra");
      xTitle = tr("Wavenumbers (cm⁻¹)");
      yTitle = tr("Transmission");
      transmission = true;

      settings.setValue("spectra/irXMin", float(m_ui->xAxisMinimum->value()));
      settings.setValue("spectra/irXMax", m_ui->xAxisMaximum->value());
      settings.setValue("spectra/irPeakWidth", float(m_ui->peakWidth->value()));
      settings.setValue("spectra/irScale", m_ui->scaleSpinBox->value());
      settings.setValue("spectra/irOffset", m_ui->offsetSpinBox->value());
      break;
    case SpectraType::Raman:
      transitions = fromMatrix(m_spectra["Raman"].col(0));
      intensities = fromMatrix(m_spectra["Raman"].col(1));
      windowName = tr("Raman Spectra");
      xTitle = tr("Wavenumbers (cm⁻¹)");
      yTitle = tr("Intensity");
      // save the plot settings
      settings.setValue("spectra/ramanXMin", m_ui->xAxisMinimum->value());
      settings.setValue("spectra/ramanXMax", m_ui->xAxisMaximum->value());
      settings.setValue("spectra/ramanPeakWidth", m_ui->peakWidth->value());
      settings.setValue("spectra/ramanScale", m_ui->scaleSpinBox->value());
      settings.setValue("spectra/ramanOffset", m_ui->offsetSpinBox->value());
      break;
    case SpectraType::NMR:
      transitions = fromMatrix(m_spectra["NMR"].col(0));
      intensities = fromMatrix(m_spectra["NMR"].col(1));
      windowName = tr("NMR Spectra");
      xTitle = tr("Chemical Shift (ppm)");
      yTitle = tr("Intensity");
      // save the plot settings
      settings.setValue("spectra/nmrXMin", m_ui->xAxisMinimum->value());
      settings.setValue("spectra/nmrXMax", m_ui->xAxisMaximum->value());
      settings.setValue("spectra/nmrPeakWidth", m_ui->peakWidth->value());
      settings.setValue("spectra/nmrScale", m_ui->scaleSpinBox->value());
      settings.setValue("spectra/nmrOffset", m_ui->offsetSpinBox->value());
      break;
    case SpectraType::Electronic:
      transitions = fromMatrix(m_spectra["Electronic"].col(0));
      intensities = fromMatrix(m_spectra["Electronic"].col(1));
      windowName = tr("Electronic Spectra");
      QString xWave = tr("Wavelength (nm)");
      xTitle = tr("Energy (eV)");
      yTitle = tr("Intensity");
      // save settings
      settings.setValue("spectra/electronicXMin", m_ui->xAxisMinimum->value());
      settings.setValue("spectra/electronicXMax", m_ui->xAxisMaximum->value());
      settings.setValue("spectra/electronicPeakWidth",
                        m_ui->peakWidth->value());
      settings.setValue("spectra/electronicScale", m_ui->scaleSpinBox->value());
      settings.setValue("spectra/electronicOffset",
                        m_ui->offsetSpinBox->value());
      break;
    case SpectraType::CircularDichroism:
      transitions = fromMatrix(m_spectra["Electronic"].col(0));
      // check if electronic has a third column
      if (m_spectra["Electronic"].cols() > 2)
        intensities = fromMatrix(m_spectra["Electronic"].col(2));
      else // grab it from the CD data
        intensities = fromMatrix(m_spectra["CircularDichroism"].col(1));
      windowName = tr("Circular Dichroism Spectra");
      xTitle = tr("Energy (eV)");
      yTitle = tr("Intensity");
      // save settings
      settings.setValue("spectra/CDXMin", m_ui->xAxisMinimum->value());
      settings.setValue("spectra/CDXMax", m_ui->xAxisMaximum->value());
      settings.setValue("spectra/CDPeakWidth", m_ui->peakWidth->value());
      settings.setValue("spectra/CDScale", m_ui->scaleSpinBox->value());
      settings.setValue("spectra/CDOffset", m_ui->offsetSpinBox->value());
      break;
    case SpectraType::DensityOfStates:
      transitions = fromMatrix(m_spectra["DensityOfStates"].col(0));
      intensities = fromMatrix(m_spectra["DensityOfStates"].col(1));
      windowName = tr("Density of States");
      xTitle = tr("Energy (eV)");
      yTitle = tr("Intensity");
      // save settings
      settings.setValue("spectra/dosXMin", m_ui->xAxisMinimum->value());
      settings.setValue("spectra/dosXMax", m_ui->xAxisMaximum->value());
      settings.setValue("spectra/dosPeakWidth", m_ui->peakWidth->value());
      settings.setValue("spectra/dosScale", m_ui->scaleSpinBox->value());
      settings.setValue("spectra/dosOffset", m_ui->offsetSpinBox->value());
      break;
  }
  setWindowTitle(windowName);

  // update the data table
  m_ui->dataTable->setRowCount(transitions.size());
  m_ui->dataTable->setColumnCount(2);
  for (auto i = 0; i < transitions.size(); ++i) {
    // frequency or energy
    QTableWidgetItem* item =
      new QTableWidgetItem(QString::number(transitions[i], 'f', 4));
    m_ui->dataTable->setItem(i, 0, item);
    // intensities
    item = new QTableWidgetItem(QString::number(intensities[i], 'f', 4));
    m_ui->dataTable->setItem(i, 1, item);
  }

  double maxIntensity = 0.0f;
  for (auto intensity : intensities) {
    if (intensity > maxIntensity)
      maxIntensity = intensity;
  }

  // if transmission for IR, set the max intensity to 100
  if (type == SpectraType::Infrared)
    maxIntensity = 100.0;

  if (maxIntensity < 1.0)
    maxIntensity = 1.0;

  // update the spin boxes
  m_ui->yAxisMaximum->setValue(maxIntensity);
  m_ui->yAxisMinimum->setMinimum(0.0);
  // if CD, set the minimum too
  if (type == SpectraType::CircularDichroism) {
    m_ui->yAxisMinimum->setMinimum(-maxIntensity * 2.0);
    m_ui->yAxisMinimum->setValue(-maxIntensity);
  }

  // now compose the plot data
  float scale = m_ui->scaleSpinBox->value();
  float offset = m_ui->offsetSpinBox->value();
  float fwhm = m_ui->peakWidth->value();

  float xMin = m_ui->xAxisMinimum->value();
  float xMax = m_ui->xAxisMaximum->value();

  float start = std::min(xMin, xMax);
  float end = std::max(xMin, xMax);
  // for some spectra, we need to take small steps, so we scale the x axis
  float xScale = 1.0;
  if (type == SpectraType::Electronic || type == SpectraType::CircularDichroism)
    xScale = 1.0f / 0.05f;

  float stickWidth = fwhm / (xScale * 30.0);

  for (unsigned int x = round(start * xScale); x < round(end * xScale); ++x) {
    float xValue = static_cast<float>(x) / xScale;
    xData.push_back(xValue);
    yData.push_back(0.0f);
    yStick.push_back(0.0f);

    // now we add up the intensity from any frequency
    for (auto index = 0; index < transitions.size(); ++index) {
      float freq = transitions[index];
      float peak = intensities[index];

      float intensity = scaleAndBlur(xValue, freq, peak, scale, offset, fwhm);
      float stick = scaleAndBlur(xValue, freq, peak, scale, offset, stickWidth);

      yData.back() += intensity;
      yStick.back() += stick;
    }
    // if transmission, we need to invert the intensity
    if (transmission) {
      float trans = 1.0f - (yData.back() / (maxIntensity * 1.25));
      yData.back() = trans * 100.0; // percent
      trans = 1.0f - (yStick.back() / maxIntensity);
      yStick.back() = trans * 100.0; // percent
    }
  }

  auto* chart = chartWidget();
  chart->clearPlots();
  chart->setXAxisTitle(xTitle.toStdString());
  chart->setYAxisTitle(yTitle.toStdString());
  unsigned int fontSize = m_ui->fontSizeCombo->currentText().toInt();
  chart->setFontSize(fontSize);
  float lineWidth = m_ui->lineWidthSpinBox->value();
  chart->setLineWidth(lineWidth);

  // get the spectra color
  QColor spectraColor =
    settings.value("spectra/calculatedColor", black).value<QColor>();
  VTK::color4ub calculatedColor = {
    static_cast<unsigned char>(spectraColor.red()),
    static_cast<unsigned char>(spectraColor.green()),
    static_cast<unsigned char>(spectraColor.blue()),
    static_cast<unsigned char>(spectraColor.alpha())
  };
  chart->addPlot(xData, yData, calculatedColor);
  VTK::color4ub importedColor = { 255, 0, 0, 255 };
  chart->addSeries(yStick, importedColor);

  // axis limits
  float xAxisMin = m_ui->xAxisMinimum->value();
  float xAxisMax = m_ui->xAxisMaximum->value();
  float yAxisMin = m_ui->yAxisMinimum->value();
  float yAxisMax = m_ui->yAxisMaximum->value();

  chart->setXAxisLimits(xAxisMin, xAxisMax);
  chart->setYAxisLimits(yAxisMin, yAxisMax);

  // re-enable the options
  connectOptions();
}

VTK::ChartWidget* SpectraDialog::chartWidget()
{
  return m_ui->plot;
}

void SpectraDialog::toggleOptions()
{
  if (m_ui->tab_widget->isHidden()) {
    m_ui->tab_widget->show();
    // todo: show the data table
    // m_ui->dataTable->show();
    // m_ui->push_exportData->show();
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
