/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "spectra.h"
#include "vibrationdialog.h"

#include <avogadro/core/array.h>
#include <avogadro/core/variant.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/molecule.h>

#include <avogadro/vtk/chartdialog.h>
#include <avogadro/vtk/chartwidget.h>

#include <QAction>
#include <QDebug>
#include <QtCore/QTimer>
#include <QtWidgets/QFileDialog>

namespace Avogadro::QtPlugins {

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

Spectra::Spectra(QObject* p)
  : ExtensionPlugin(p), m_molecule(nullptr), m_dialog(nullptr),
    m_timer(nullptr), m_mode(0), m_amplitude(20)
{
  auto* action = new QAction(this);
  action->setEnabled(false);
  action->setText(tr("Vibrational Modes…"));
  connect(action, SIGNAL(triggered()), SLOT(openDialog()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(false);
  action->setText(tr("Spectra…"));
  connect(action, SIGNAL(triggered()), SLOT(showSpectraChart()));
  m_actions.push_back(action);
}

Spectra::~Spectra() {}

QList<QAction*> Spectra::actions() const
{
  return m_actions;
}

QStringList Spectra::menuPath(QAction*) const
{
  QStringList path;
  path << tr("&Analysis");
  return path;
}

void Spectra::setMolecule(QtGui::Molecule* mol)
{
  bool isVibrational(false);
  if (mol->vibrationFrequencies().size())
    isVibrational = true;

  m_actions[0]->setEnabled(isVibrational);
  m_actions[1]->setEnabled(isVibrational);
  m_molecule = mol;
  if (m_dialog)
    m_dialog->setMolecule(mol);

  if (isVibrational)
    openDialog();
}

void Spectra::registerCommands()
{
  emit registerCommand("showVibrations",
                       tr("Show the vibrational modes dialog."));
  emit registerCommand("setVibrationalMode", tr("Set the vibrational mode."));
  emit registerCommand("setVibrationalAmplitude",
                       tr("Set the vibrational amplitude."));
  emit registerCommand("startVibrationAnimation",
                       tr("Start the vibrational animation."));
  emit registerCommand("stopVibrationAnimation",
                       tr("Stop the vibrational animation."));
}

bool Spectra::handleCommand(const QString& command, const QVariantMap& options)
{
  if (m_molecule == nullptr)
    return false; // No molecule to handle the command.

  if (command == "showVibrations") {
    openDialog();
    return true;
  } else if (command == "setVibrationalMode") {
    if (options.contains("mode")) {
      setMode(options["mode"].toInt());
      return true;
    }
  } else if (command == "setVibrationalAmplitude") {
    if (options.contains("amplitude")) {
      setAmplitude(options["amplitude"].toInt());
      return true;
    }
  } else if (command == "startVibrationAnimation") {
    startVibrationAnimation();
    return true;
  } else if (command == "stopVibrationAnimation") {
    stopVibrationAnimation();
    return true;
  }
  return false;
}

void Spectra::setMode(int mode)
{
  if (mode >= 0 &&
      mode < static_cast<int>(m_molecule->vibrationFrequencies().size())) {
    m_mode = mode;

    // Now calculate the frames and set them on the molecule.
    m_molecule->setCoordinate3d(0);
    Core::Array<Vector3> atomPositions = m_molecule->atomPositions3d();
    Core::Array<Vector3> atomDisplacements = m_molecule->vibrationLx(mode);
    // TODO: needs an option (show forces or not)
    double factor = 0.01 * m_amplitude;
    Index atom = 0;
    for (Vector3& v : atomDisplacements) {
      v *= 10.0 * factor;
      m_molecule->setForceVector(atom, v);
      ++atom;
    }
    m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Added);

    int frames = 5; // TODO: needs an option
    int frameCounter = 0;
    m_molecule->setCoordinate3d(atomPositions, frameCounter++);

    // Current coords + displacement.
    for (int i = 1; i <= frames; ++i) {
      Core::Array<Vector3> framePositions;
      for (Index atom = 0; atom < m_molecule->atomCount(); ++atom) {
        framePositions.push_back(atomPositions[atom] + atomDisplacements[atom] *
                                                         factor *
                                                         (double(i) / frames));
      }
      m_molecule->setCoordinate3d(framePositions, frameCounter++);
    }
    // + displacement back to original.
    for (int i = frames - 1; i >= 0; --i) {
      Core::Array<Vector3> framePositions;
      for (Index atom = 0; atom < m_molecule->atomCount(); ++atom) {
        framePositions.push_back(atomPositions[atom] + atomDisplacements[atom] *
                                                         factor *
                                                         (double(i) / frames));
      }
      m_molecule->setCoordinate3d(framePositions, frameCounter++);
    }
    // Current coords - displacement.
    for (int i = 1; i <= frames; ++i) {
      Core::Array<Vector3> framePositions;
      for (Index atom = 0; atom < m_molecule->atomCount(); ++atom) {
        framePositions.push_back(atomPositions[atom] - atomDisplacements[atom] *
                                                         factor *
                                                         (double(i) / frames));
      }
      m_molecule->setCoordinate3d(framePositions, frameCounter++);
    }
    // - displacement back to original.
    for (int i = frames - 1; i >= 0; --i) {
      Core::Array<Vector3> framePositions;
      for (Index atom = 0; atom < m_molecule->atomCount(); ++atom) {
        framePositions.push_back(atomPositions[atom] - atomDisplacements[atom] *
                                                         factor *
                                                         (double(i) / frames));
      }
      m_molecule->setCoordinate3d(framePositions, frameCounter++);
    }
  }
}

void Spectra::setAmplitude(int amplitude)
{
  m_amplitude = amplitude;
  setMode(m_mode);
}

void Spectra::startVibrationAnimation()
{
  // First calculate our frames, and then start our timer.
  m_totalFrames = m_molecule->coordinate3dCount();
  m_currentFrame = 0;

  if (!m_timer) {
    m_timer = new QTimer(this);
    connect(m_timer, SIGNAL(timeout()), SLOT(advanceFrame()));
  }
  if (!m_timer->isActive()) {
    m_timer->start(50);
  }
}

void Spectra::stopVibrationAnimation()
{
  if (m_timer && m_timer->isActive()) {
    m_timer->stop();
    m_molecule->setCoordinate3d(0);
    m_currentFrame = 0;
    m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Added);
  }
}

void Spectra::openDialog()
{
  if (!m_dialog) {
    m_dialog = new VibrationDialog(qobject_cast<QWidget*>(parent()));
    connect(m_dialog, SIGNAL(modeChanged(int)), SLOT(setMode(int)));
    connect(m_dialog, SIGNAL(amplitudeChanged(int)), SLOT(setAmplitude(int)));
    connect(m_dialog, SIGNAL(startAnimation()),
            SLOT(startVibrationAnimation()));
    connect(m_dialog, SIGNAL(stopAnimation()), SLOT(stopVibrationAnimation()));
  }
  if (m_molecule)
    m_dialog->setMolecule(m_molecule);
  m_dialog->show();
}

void Spectra::showSpectraChart()
{
  if (m_molecule == nullptr || m_molecule->vibrationFrequencies().empty())
    return;

  std::vector<float> xData;
  std::vector<float> yData;
  std::vector<float> yStick;

  float maxIntensity = 0.0f;
  for (auto intensity : m_molecule->vibrationIRIntensities()) {
    if (intensity > maxIntensity)
      maxIntensity = intensity;
  }

  float scale = 1.0;
  float shift = 0.0;
  float fwhm = 30.0;
  for (unsigned int x = 0; x < 4000; ++x) {
    float xValue = static_cast<float>(x);
    xData.push_back(xValue);
    yData.push_back(0.0f);
    yStick.push_back(0.0f);

    // now we add up the intensity from any frequency
    for (auto index = 0; index < m_molecule->vibrationFrequencies().size();
         ++index) {
      float freq = m_molecule->vibrationFrequencies()[index];
      float peak = m_molecule->vibrationIRIntensities()[index];
      float intensity = scaleAndBlur(xValue, freq, peak, scale, shift, fwhm);
      float stick = scaleAndBlur(xValue, freq, peak, scale, shift, 0.0);

      yData.back() += intensity;
      yStick.back() += stick;
    }
  }

auto xTitle = tr("Wavenumbers (cm⁻¹)");
auto yTitle = tr("Transmission");
auto windowName = tr("Vibrational Spectra");

if (!m_chartDialog) {
  m_chartDialog.reset(
    new VTK::ChartDialog(qobject_cast<QWidget*>(this->parent())));
}

m_chartDialog->setWindowTitle(windowName);
auto* chart = m_chartDialog->chartWidget();
chart->clearPlots();
chart->setXAxisTitle(xTitle.toStdString());
chart->setYAxisTitle(yTitle.toStdString());
chart->addPlot(xData, yData, VTK::color4ub{ 0, 0, 0, 255 });
chart->setXAxisLimits(4000.0, 0.0);
chart->setYAxisLimits(maxIntensity, 0.0);
m_chartDialog->show();
}

void Spectra::advanceFrame()
{
  if (++m_currentFrame >= m_totalFrames)
    m_currentFrame = 0;
  m_molecule->setCoordinate3d(m_currentFrame);
  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Added);
}
} // namespace Avogadro::QtPlugins
