/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2015 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "spectra.h"
#include "vibrationdialog.h"

#include <avogadro/core/array.h>
#include <avogadro/core/variant.h>
#include <avogadro/core/vector.h>

#include <QtCore/QTimer>
#include <QtWidgets/QAction>
#include <QtWidgets/QFileDialog>
#include <avogadro/qtgui/molecule.h>

namespace Avogadro {
namespace QtPlugins {

Spectra::Spectra(QObject* p)
  : ExtensionPlugin(p), m_molecule(nullptr), m_dialog(nullptr),
    m_timer(nullptr), m_mode(0), m_amplitude(20)
{
  QAction* action = new QAction(this);
  action->setEnabled(false);
  action->setText(tr("Vibrational modes..."));
  connect(action, SIGNAL(triggered()), SLOT(openDialog()));
  m_actions.push_back(action);
}

Spectra::~Spectra()
{
}

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
  m_molecule = mol;
  if (m_dialog)
    m_dialog->setMolecule(mol);
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

    int frames = 5;
    int frameCounter = 0;
    m_molecule->setCoordinate3d(atomPositions, frameCounter++);

    double factor = 0.01 * m_amplitude;

    // Current coords + displacement.
    for (int i = 1; i <= frames; ++i) {
      Core::Array<Vector3> framePositions;
      for (Index atom = 0; atom < m_molecule->atomCount(); ++atom) {
        framePositions.push_back(atomPositions[atom] +
                                 atomDisplacements[atom] * factor *
                                   (double(i) / frames));
      }
      m_molecule->setCoordinate3d(framePositions, frameCounter++);
    }
    // + displacement back to original.
    for (int i = frames - 1; i >= 0; --i) {
      Core::Array<Vector3> framePositions;
      for (Index atom = 0; atom < m_molecule->atomCount(); ++atom) {
        framePositions.push_back(atomPositions[atom] +
                                 atomDisplacements[atom] * factor *
                                   (double(i) / frames));
      }
      m_molecule->setCoordinate3d(framePositions, frameCounter++);
    }
    // Current coords - displacement.
    for (int i = 1; i <= frames; ++i) {
      Core::Array<Vector3> framePositions;
      for (Index atom = 0; atom < m_molecule->atomCount(); ++atom) {
        framePositions.push_back(atomPositions[atom] -
                                 atomDisplacements[atom] * factor *
                                   (double(i) / frames));
      }
      m_molecule->setCoordinate3d(framePositions, frameCounter++);
    }
    // - displacement back to original.
    for (int i = frames - 1; i >= 0; --i) {
      Core::Array<Vector3> framePositions;
      for (Index atom = 0; atom < m_molecule->atomCount(); ++atom) {
        framePositions.push_back(atomPositions[atom] -
                                 atomDisplacements[atom] * factor *
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

void Spectra::advanceFrame()
{
  if (++m_currentFrame >= m_totalFrames)
    m_currentFrame = 0;
  m_molecule->setCoordinate3d(m_currentFrame);
  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Added);
}
}
}
