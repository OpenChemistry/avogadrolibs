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
#include <avogadro/qtgui/chartwidget.h>

using Avogadro::Core::Molecule;
using Avogadro::QtGui::ChartWidget;

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

float closestTo(float x, float peak, float intensity, float scale = 1.0,
                float shift = 0.0, float xScale = 1.0)
{
  // return peak intensity if x is closer to the peak than another point
  // scaled by scale and shifted by shift
  float scaled_peak = (peak - shift) / scale;
  float delta = x - scaled_peak;
  // xScale is the reciprocal of the space between points
  // (i.e., used to generate many points in the loop)
  float peak_to_peak = 1.0 / xScale;
  return (fabs(delta) < peak_to_peak / 2.0) ? intensity : 0.0;
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
  connect(m_ui->push_exportData, SIGNAL(clicked()), this, SLOT(exportData()));
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

void SpectraDialog::mouseDoubleClickEvent(QMouseEvent* e)
{
  auto* chart = chartWidget();
  if (chart)
    chart->resetZoom();
}

void SpectraDialog::updateElementCombo()
{
  // update the element combo box
  disconnect(m_ui->elementCombo, SIGNAL(currentIndexChanged(int)), this,
             SLOT(changeSpectra()));
  m_ui->elementCombo->clear();

  // go through the elements in atomic number order
  // make a copy of the vector
  std::vector<unsigned char> elements = m_elements;
  std::sort(elements.begin(), elements.end());

  // add the unique elements, with the element number as the data
  for (auto& element : elements) {
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
  changeSpectra(); // default to 1H
}

void SpectraDialog::changeSpectra()
{
  // based on the current spectra type, update the options
  // and prep the spectra for plotting
  QSettings settings;

  disconnectOptions();

  // what type of spectra are we plotting?
  SpectraType type =
    static_cast<SpectraType>(m_ui->combo_spectra->currentData().toInt());

  // only show for NMR
  m_ui->elementCombo->hide();
  // todo: some spectra might want to swtich units

  m_transitions.clear();
  m_intensities.clear();

  switch (type) {
    case SpectraType::Infrared:
      m_transitions = fromMatrix(m_spectra["IR"].col(0));
      m_intensities = fromMatrix(m_spectra["IR"].col(1));

      settings.beginGroup("spectra/ir");
      m_ui->scaleSpinBox->setValue(settings.value("scale", 1.0).toDouble());
      m_ui->offsetSpinBox->setValue(settings.value("offset", 0.0).toDouble());
      m_ui->xAxisMinimum->setValue(settings.value("xmin", 4000.0).toDouble());
      m_ui->xAxisMaximum->setValue(settings.value("xmax", 400.0).toDouble());
      m_ui->peakWidth->setValue(settings.value("fwhm", 30.0).toDouble());
      settings.endGroup();
      break;
    case SpectraType::Raman:
      m_transitions = fromMatrix(m_spectra["Raman"].col(0));
      m_intensities = fromMatrix(m_spectra["Raman"].col(1));

      settings.beginGroup("spectra/raman");
      m_ui->scaleSpinBox->setValue(settings.value("scale", 1.0).toDouble());
      m_ui->offsetSpinBox->setValue(settings.value("offset", 0.0).toDouble());
      m_ui->xAxisMinimum->setValue(settings.value("xmin", 0.0).toDouble());
      m_ui->xAxisMaximum->setValue(settings.value("xmax", 4000.0).toDouble());
      m_ui->peakWidth->setValue(settings.value("fwhm", 30.0).toDouble());
      settings.endGroup();
      break;
    case SpectraType::NMR:
      // settings handled per-element below
      m_ui->elementCombo->show();
      break;
    case SpectraType::Electronic:
      m_transitions = fromMatrix(m_spectra["Electronic"].col(0));
      m_intensities = fromMatrix(m_spectra["Electronic"].col(1));

      settings.beginGroup("spectra/electronic");
      m_ui->scaleSpinBox->setValue(settings.value("scale", 1.0).toDouble());
      m_ui->offsetSpinBox->setValue(settings.value("offset", 0.0).toDouble());
      // in eV
      m_ui->xAxisMinimum->setValue(settings.value("xmin", 5.0).toDouble());
      m_ui->xAxisMaximum->setValue(settings.value("xmax", 1.0).toDouble());
      m_ui->peakWidth->setValue(settings.value("fwhm", 0.1).toDouble());
      settings.endGroup();
      break;
    case SpectraType::CircularDichroism:
      m_transitions = fromMatrix(m_spectra["Electronic"].col(0));
      // check if electronic has a third column
      if (m_spectra["Electronic"].cols() > 2)
        m_intensities = fromMatrix(m_spectra["Electronic"].col(2));
      else // grab it from the CD data
        m_intensities = fromMatrix(m_spectra["CircularDichroism"].col(1));

      settings.beginGroup("spectra/cd");
      m_ui->scaleSpinBox->setValue(settings.value("scale", 1.0).toDouble());
      m_ui->offsetSpinBox->setValue(settings.value("offset", 0.0).toDouble());
      // default to eV units
      m_ui->xAxisMinimum->setValue(settings.value("xmin", 5.0).toDouble());
      m_ui->xAxisMaximum->setValue(settings.value("xmax", 1.0).toDouble());
      m_ui->peakWidth->setValue(settings.value("fwhm", 0.1).toDouble());
      settings.endGroup();
      break;
    case SpectraType::DensityOfStates:
      m_transitions = fromMatrix(m_spectra["DensityOfStates"].col(0));
      m_intensities = fromMatrix(m_spectra["DensityOfStates"].col(1));

      settings.beginGroup("spectra/dos");
      m_ui->scaleSpinBox->setValue(settings.value("scale", 1.0).toDouble());
      m_ui->offsetSpinBox->setValue(settings.value("offset", 0.0).toDouble());
      m_ui->xAxisMinimum->setValue(settings.value("xmin", -50.0).toDouble());
      m_ui->xAxisMaximum->setValue(settings.value("xmax", 50.0).toDouble());
      m_ui->peakWidth->setValue(settings.value("fwhm", 0.1).toDouble());
      settings.endGroup();
      break;
  }

  // a bunch of special work depending on the NMR element
  if (type == SpectraType::NMR) {
    // get the element
    int element = m_ui->elementCombo->currentData().toInt();

    settings.beginGroup(QString("spectra/nmr/%1").arg(element));
    m_ui->scaleSpinBox->setValue(settings.value("scale", 1.0).toDouble());
    m_ui->peakWidth->setValue(settings.value("fwhm", 0.1).toDouble());

    // tweak the default axis range
    // based on https://imserc.northwestern.edu/guide/eNMR/chem/NMRnuclei.html
    // offsets are approximate from a few calculations
    // .. to at least provide a starting point
    switch (element) {
      case 1: // 1H
        m_ui->xAxisMinimum->setValue(settings.value("xmin", 12.0).toDouble());
        m_ui->xAxisMaximum->setValue(settings.value("xmax", 0.0).toDouble());
        m_ui->offsetSpinBox->setValue(
          settings.value("offset", 31.876).toDouble());
        break;
      case 3: // 7Li
        m_ui->xAxisMinimum->setValue(settings.value("xmin", -16.0).toDouble());
        m_ui->xAxisMaximum->setValue(settings.value("xmax", 11.0).toDouble());
        // TODO: offset
        m_ui->offsetSpinBox->setValue(settings.value("offset", 0.0).toDouble());
        break;
      case 5: // 11B
        m_ui->xAxisMinimum->setValue(settings.value("xmin", 100.0).toDouble());
        m_ui->xAxisMaximum->setValue(settings.value("xmax", -120.0).toDouble());
        m_ui->offsetSpinBox->setValue(
          settings.value("offset", 109.774).toDouble());
        break;
      case 6: // 13C
        m_ui->xAxisMinimum->setValue(settings.value("xmin", 200.0).toDouble());
        m_ui->xAxisMaximum->setValue(settings.value("xmax", 0.0).toDouble());
        m_ui->offsetSpinBox->setValue(
          settings.value("offset", 192.038).toDouble());
        break;
      case 7: // 15N
        m_ui->xAxisMinimum->setValue(settings.value("xmin", 800.0).toDouble());
        m_ui->xAxisMaximum->setValue(settings.value("xmax", 0.0).toDouble());
        m_ui->offsetSpinBox->setValue(
          settings.value("offset", -106.738).toDouble());
        break;
      case 8: // 17O
        m_ui->xAxisMinimum->setValue(settings.value("xmin", 1600.0).toDouble());
        m_ui->xAxisMaximum->setValue(settings.value("xmax", -50.0).toDouble());
        m_ui->offsetSpinBox->setValue(
          settings.value("offset", 347.782).toDouble());
        break;
      case 9: // 19F
        m_ui->xAxisMinimum->setValue(settings.value("xmin", 60.0).toDouble());
        m_ui->xAxisMaximum->setValue(settings.value("xmax", -300.0).toDouble());
        m_ui->offsetSpinBox->setValue(
          settings.value("offset", 206.735).toDouble());
        break;
      case 14: // 29Si
        m_ui->xAxisMinimum->setValue(settings.value("xmin", 50.0).toDouble());
        m_ui->xAxisMaximum->setValue(settings.value("xmax", -200.0).toDouble());
        m_ui->offsetSpinBox->setValue(
          settings.value("offset", 400.876).toDouble());
        break;
      case 15: // 31P
        m_ui->xAxisMinimum->setValue(settings.value("xmin", 250.0).toDouble());
        m_ui->xAxisMaximum->setValue(settings.value("xmax", -250.0).toDouble());
        m_ui->offsetSpinBox->setValue(
          settings.value("offset", 392.841).toDouble());
        break;
      default:
        m_ui->xAxisMinimum->setValue(settings.value("xmax", 100.0).toDouble());
        m_ui->xAxisMaximum->setValue(settings.value("xmax", -100.0).toDouble());
        m_ui->offsetSpinBox->setValue(settings.value("offset", 0.0).toDouble());
        break;
    }
    settings.endGroup();

    // the default NMR data has all the atoms in it,
    // so we need to loop through m_elements to filter
    MatrixX nmr = m_spectra["NMR"];

    for (int i = 0; i < m_elements.size(); ++i) {
      if (m_elements[i] == element) {
        m_transitions.push_back(nmr(i, 0));
      }
    }
    // fill the intensities with 1.0
    m_intensities.resize(m_transitions.size(), 1.0);
  }
  // other spectra transitions and intensities are already set

  // update the data table
  double maxIntensity = 0.0;
  m_ui->dataTable->setRowCount(m_transitions.size());
  m_ui->dataTable->setColumnCount(2);
  for (auto i = 0; i < m_transitions.size(); ++i) {
    // frequency or energy
    QTableWidgetItem* item =
      new QTableWidgetItem(QString::number(m_transitions[i], 'f', 4));
    m_ui->dataTable->setItem(i, 0, item);
    // intensities
    item = new QTableWidgetItem(QString::number(m_intensities[i], 'f', 4));
    m_ui->dataTable->setItem(i, 1, item);

    if (m_intensities[i] > maxIntensity)
      maxIntensity = m_intensities[i];
  }

  // update the spin boxes
  m_ui->yAxisMaximum->setValue(maxIntensity);
  m_ui->yAxisMinimum->setMinimum(0.0);
  // if CD, set the minimum too
  if (type == SpectraType::CircularDichroism) {
    m_ui->yAxisMinimum->setMinimum(-maxIntensity * 2.0);
    m_ui->yAxisMinimum->setValue(-maxIntensity);
  }
  if (type == SpectraType::Infrared) {
    m_ui->yAxisMaximum->setValue(102.0); // transmission
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
  settings.beginGroup("spectra");
  // update the dialog with saved settings

  // font size
  int fontSize = settings.value("fontSize", 12).toInt();
  m_ui->fontSizeCombo->setCurrentText(QString::number(fontSize));
  // line width
  float lineWidth = settings.value("lineWidth", 1.0).toFloat();
  m_ui->lineWidthSpinBox->setValue(lineWidth);

  // TODO: other bits
  settings.endGroup();
}

void SpectraDialog::changeBackgroundColor()
{
  QSettings settings;
  QColor current =
    settings.value("spectra/backgroundColor", white).value<QColor>();
  QColor color =
    QColorDialog::getColor(current, this, tr("Select Background Color"),
                           QColorDialog::ShowAlphaChannel);
  if (color.isValid() && color != current) {
    settings.setValue("spectra/backgroundColor", color);
    auto* chart = chartWidget();
    if (chart != nullptr) {
      QtGui::color4ub ubColor = { static_cast<unsigned char>(color.red()),
                                  static_cast<unsigned char>(color.green()),
                                  static_cast<unsigned char>(color.blue()),
                                  static_cast<unsigned char>(color.alpha()) };
      chart->setBackgroundColor(ubColor);
    }
    updatePlot();
  }
}

void SpectraDialog::exportData() {}

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
  // TODO: switch units for electronic and CD
  QString xWave = tr("Wavelength (nm)");
  QString xFreq = tr("Frequency (Hz)");

  bool transmission = false;
  // get the raw data from the spectra map
  switch (type) {
    case SpectraType::Infrared:
      windowName = tr("Vibrational Spectra");
      xTitle = tr("Wavenumbers (cm⁻¹)");
      yTitle = tr("Transmission");
      transmission = true;

      settings.beginGroup("spectra/ir");
      settings.setValue("xmin", float(m_ui->xAxisMinimum->value()));
      settings.setValue("xmax", m_ui->xAxisMaximum->value());
      settings.setValue("fwhm", float(m_ui->peakWidth->value()));
      settings.setValue("scale", m_ui->scaleSpinBox->value());
      settings.setValue("offset", m_ui->offsetSpinBox->value());
      settings.endGroup();
      break;
    case SpectraType::Raman:
      windowName = tr("Raman Spectra");
      xTitle = tr("Wavenumbers (cm⁻¹)");
      yTitle = tr("Intensity");
      // save the plot settings
      settings.beginGroup("spectra/raman");
      settings.setValue("xmin", m_ui->xAxisMinimum->value());
      settings.setValue("xmax", m_ui->xAxisMaximum->value());
      settings.setValue("fwhm", m_ui->peakWidth->value());
      settings.setValue("scale", m_ui->scaleSpinBox->value());
      settings.setValue("offset", m_ui->offsetSpinBox->value());
      settings.endGroup();
      break;
    case SpectraType::NMR:
      windowName = tr("NMR Spectra");
      xTitle = tr("Chemical Shift (ppm)");
      yTitle = tr("Intensity");
      // save the plot settings on a per element basis
      settings.beginGroup(QString("spectra/nmr/%1")
                            .arg(m_ui->elementCombo->currentData().toInt()));
      settings.setValue("xmin", m_ui->xAxisMinimum->value());
      settings.setValue("xmax", m_ui->xAxisMaximum->value());
      settings.setValue("fwhm", m_ui->peakWidth->value());
      settings.setValue("scale", m_ui->scaleSpinBox->value());
      settings.setValue("offset", m_ui->offsetSpinBox->value());
      settings.endGroup();
      break;
    case SpectraType::Electronic:
      windowName = tr("Electronic Spectra");
      xTitle = tr("Energy (eV)");
      yTitle = tr("Intensity");
      // save settings
      settings.beginGroup("spectra/electronic");
      settings.setValue("xmin", m_ui->xAxisMinimum->value());
      settings.setValue("xmax", m_ui->xAxisMaximum->value());
      settings.setValue("fwhm", m_ui->peakWidth->value());
      settings.setValue("scale", m_ui->scaleSpinBox->value());
      settings.setValue("offset", m_ui->offsetSpinBox->value());
      settings.endGroup();
      break;
    case SpectraType::CircularDichroism:
      windowName = tr("Circular Dichroism Spectra");
      xTitle = tr("Energy (eV)");
      yTitle = tr("Intensity");
      // save settings
      settings.beginGroup("spectra/cd");
      settings.setValue("xmin", m_ui->xAxisMinimum->value());
      settings.setValue("xmax", m_ui->xAxisMaximum->value());
      settings.setValue("fwhm", m_ui->peakWidth->value());
      settings.setValue("scale", m_ui->scaleSpinBox->value());
      settings.setValue("offset", m_ui->offsetSpinBox->value());
      settings.endGroup();
      break;
    case SpectraType::DensityOfStates:
      windowName = tr("Density of States");
      xTitle = tr("Energy (eV)");
      yTitle = tr("Density");
      // save settings
      settings.beginGroup("spectra/dos");
      settings.setValue("xmin", m_ui->xAxisMinimum->value());
      settings.setValue("xmax", m_ui->xAxisMaximum->value());
      settings.setValue("fwhm", m_ui->peakWidth->value());
      settings.setValue("scale", m_ui->scaleSpinBox->value());
      settings.setValue("offset", m_ui->offsetSpinBox->value());
      settings.endGroup();
      break;
  }
  setWindowTitle(windowName);

  double maxIntensity = 0.0f;
  for (auto intensity : m_intensities) {
    if (intensity > maxIntensity)
      maxIntensity = intensity;
  }

  // if transmission for IR, set the max intensity to 100
  if (type == SpectraType::Infrared)
    maxIntensity = 100.0;

  if (maxIntensity < 1.0)
    maxIntensity = 1.0;

  // now compose the plot data
  float scale = m_ui->scaleSpinBox->value();
  float offset = m_ui->offsetSpinBox->value();
  // NMR offsets should be inverted
  if (type == SpectraType::NMR) {
    scale = -scale;
  }

  float fwhm = m_ui->peakWidth->value();

  float xMin = m_ui->xAxisMinimum->value();
  float xMax = m_ui->xAxisMaximum->value();

  float start = std::min(xMin, xMax);
  float end = std::max(xMin, xMax);
  // for some spectra, we need to take small steps, so we scale the x axis
  float xScale = 1.0;
  if (type == SpectraType::Electronic || type == SpectraType::CircularDichroism)
    xScale = 1.0f / 0.01f;
  else if (type == SpectraType::NMR)
    xScale = 1.0f / 0.01f;

  // TODO: process an experimental spectrum via interpolation
  for (unsigned int x = round(start * xScale); x < round(end * xScale); ++x) {
    float xValue = static_cast<float>(x) / xScale;
    xData.push_back(xValue);
    yData.push_back(0.0f);
    yStick.push_back(0.0f);

    // now we add up the intensity from any frequency
    for (auto index = 0; index < m_transitions.size(); ++index) {
      float freq = m_transitions[index];
      float peak = m_intensities[index];

      float intensity = scaleAndBlur(xValue, freq, peak, scale, offset, fwhm);
      float stick = closestTo(xValue, freq, peak, scale, offset, xScale);

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
  chart->setXAxisTitle(xTitle);
  chart->setYAxisTitle(yTitle);
  unsigned int fontSize = m_ui->fontSizeCombo->currentText().toInt();
  chart->setFontSize(fontSize);
  float lineWidth = m_ui->lineWidthSpinBox->value();
  chart->setLineWidth(lineWidth);
  // background color
  QColor backgroundColor =
    settings.value("spectra/backgroundColor", white).value<QColor>();
  QtGui::color4ub ubColor = {
    static_cast<unsigned char>(backgroundColor.red()),
    static_cast<unsigned char>(backgroundColor.green()),
    static_cast<unsigned char>(backgroundColor.blue()),
    static_cast<unsigned char>(backgroundColor.alpha())
  };
  chart->setBackgroundColor(ubColor);
  // axis color
  QColor axisColor =
    settings.value("spectra/foregroundColor", black).value<QColor>();
  QtGui::color4ub axisColor4ub = {
    static_cast<unsigned char>(axisColor.red()),
    static_cast<unsigned char>(axisColor.green()),
    static_cast<unsigned char>(axisColor.blue()),
    static_cast<unsigned char>(axisColor.alpha())
  };
  chart->setAxisColor(QtGui::ChartWidget::Axis::x, axisColor4ub);
  chart->setAxisColor(QtGui::ChartWidget::Axis::y, axisColor4ub);

  // get the spectra color
  QColor spectraColor =
    settings.value("spectra/calculatedColor", black).value<QColor>();
  QtGui::color4ub calculatedColor = {
    static_cast<unsigned char>(spectraColor.red()),
    static_cast<unsigned char>(spectraColor.green()),
    static_cast<unsigned char>(spectraColor.blue()),
    static_cast<unsigned char>(spectraColor.alpha())
  };
  chart->addPlot(xData, yData, calculatedColor, xTitle, tr("Smoothed"));
  // todo add hide/show raw data series
  QtGui::color4ub rawColor = { 255, 0, 0, 255 };
  chart->addSeries(yStick, rawColor, tr("Raw"));

  QColor importedColor =
    settings.value("spectra/importedColor", red).value<QColor>();
  QtGui::color4ub importedColor4ub = {
    static_cast<unsigned char>(importedColor.red()),
    static_cast<unsigned char>(importedColor.green()),
    static_cast<unsigned char>(importedColor.blue()),
    static_cast<unsigned char>(importedColor.alpha())
  };
  // TODO: add imported data here

  // axis limits
  float xAxisMin = m_ui->xAxisMinimum->value();
  float xAxisMax = m_ui->xAxisMaximum->value();
  float yAxisMin = m_ui->yAxisMinimum->value();
  float yAxisMax = m_ui->yAxisMaximum->value();

  chart->setXAxisLimits(xAxisMin, xAxisMax);
  chart->setYAxisLimits(yAxisMin, yAxisMax);

  chart->setAxisDigits(QtGui::ChartWidget::Axis::x, 4);

  // set the location if needed
  if (type == SpectraType::Infrared) {
    chart->setLegendLocation(QtGui::ChartWidget::LegendLocation::BottomRight);
  }

  // re-enable the options
  connectOptions();
  raise();
}

QtGui::ChartWidget* SpectraDialog::chartWidget()
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
