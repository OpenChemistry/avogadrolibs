/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012-2013 Kitware, Inc.
  Copyright 2018 Geoffrey Hutchison

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/
#include "surfaces.h"
#include "surfacedialog.h"

#include "gaussiansetconcurrent.h"
#include "slatersetconcurrent.h"

// Header only, but duplicate symbols if included globally...
namespace {
#include <gif.h>
}

#include <gwavi.h>

#include <avogadro/core/variant.h>

#include <avogadro/core/cube.h>
#include <avogadro/core/mesh.h>
#include <avogadro/qtgui/meshgenerator.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtopengl/activeobjects.h>
#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/core/basisset.h>
#include <avogadro/core/gaussiansettools.h>

#include <avogadro/io/fileformatmanager.h>
#include <avogadro/quantumio/gamessus.h>
#include <avogadro/quantumio/gaussiancube.h>
#include <avogadro/quantumio/gaussianfchk.h>
#include <avogadro/quantumio/molden.h>
#include <avogadro/quantumio/mopacaux.h>
#include <avogadro/quantumio/nwchemjson.h>
#include <avogadro/quantumio/nwchemlog.h>

#include <QtCore/QBuffer>
#include <QtCore/QCoreApplication>
#include <QtCore/QDebug>
#include <QtCore/QProcess>
#include <QtGui/QOpenGLFramebufferObject>
#include <QtWidgets/QAction>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressDialog>

namespace Avogadro {
namespace QtPlugins {

using Core::Cube;
using Core::GaussianSet;
using QtGui::Molecule;

class Surfaces::PIMPL
{
public:
  GifWriter* gifWriter = nullptr;
  gwavi_t* gwaviWriter = nullptr;
};

Surfaces::Surfaces(QObject* p) : ExtensionPlugin(p), d(new PIMPL())
{
  auto action = new QAction(this);
  action->setText(tr("Create Surfaces..."));
  connect(action, SIGNAL(triggered()), SLOT(surfacesActivated()));
  m_actions.push_back(action);

  // Register quantum file formats
  Io::FileFormatManager::registerFormat(new QuantumIO::GAMESSUSOutput);
  Io::FileFormatManager::registerFormat(new QuantumIO::GaussianFchk);
  Io::FileFormatManager::registerFormat(new QuantumIO::GaussianCube);
  Io::FileFormatManager::registerFormat(new QuantumIO::MoldenFile);
  Io::FileFormatManager::registerFormat(new QuantumIO::MopacAux);
  Io::FileFormatManager::registerFormat(new QuantumIO::NWChemJson);
  Io::FileFormatManager::registerFormat(new QuantumIO::NWChemLog);
}

Surfaces::~Surfaces()
{
  delete d;
  delete m_cube;
}

void Surfaces::setMolecule(QtGui::Molecule* mol)
{
  if (mol->basisSet()) {
    m_basis = mol->basisSet();
  } else if (mol->cubes().size() != 0) {
    m_cubes = mol->cubes();
  }

  m_cube = nullptr;
  m_mesh1 = nullptr;
  m_mesh2 = nullptr;
  m_molecule = mol;
}

QList<QAction*> Surfaces::actions() const
{
  return m_actions;
}

QStringList Surfaces::menuPath(QAction*) const
{
  QStringList path;
  path << tr("&Analysis");
  return path;
}

void Surfaces::surfacesActivated()
{
  if (!m_dialog) {
    m_dialog = new SurfaceDialog(qobject_cast<QWidget*>(parent()));
    connect(m_dialog, SIGNAL(calculateClickedSignal()),
            SLOT(calculateSurface()));
    connect(m_dialog, SIGNAL(recordClicked()), SLOT(recordMovie()));
    connect(m_dialog, SIGNAL(stepChanged(int)), SLOT(stepChanged(int)));
  }

  if (m_basis) {
    // we have quantum data, set up the dialog accordingly
    auto gaussian = dynamic_cast<Core::GaussianSet*>(m_basis);
    bool beta = false;
    if (gaussian) {
      auto b = gaussian->moMatrix(GaussianSet::Beta);
      if (b.rows() > 0 && b.cols() > 0)
        beta = true;
    }
    m_dialog->setupBasis(m_basis->electronCount(),
                         m_basis->molecularOrbitalCount(), beta);
  }
  if (m_cubes.size() > 0) {
    QStringList cubeNames;
    for (unsigned int i = 0; i < m_cubes.size(); ++i) {
      cubeNames << m_cubes[i]->name().c_str();
    }
    m_dialog->setupCubes(cubeNames);
  }
  m_dialog->setupSteps(m_molecule->coordinate3dCount());

  m_dialog->show();
}

void Surfaces::calculateSurface()
{
  if (!m_dialog)
    return;

  Type type = m_dialog->surfaceType();
  if (!m_cube)
    m_cube = m_molecule->addCube();
  // TODO we should add a name, type, etc.

  switch (type) {
    case VanDerWaals:
    case SolventAccessible:
    case SolventExcluded:
      calculateEDT();
      // pass a molecule and return a Cube for m_cube
      //   displayMesh();
      break;

    case ElectronDensity:
    case MolecularOrbital:
    case ElectrostaticPotential:
    case SpinDensity:
      calculateQM();
      break;

    case FromFile:
    default:
      calculateCube();
      break;
  }
}

void Surfaces::calculateEDT()
{
  // pass the molecule to the EDT, plus the surface type
  // get back a Cube object in m_cube
}

void Surfaces::calculateQM()
{
  if (!m_basis || !m_dialog)
    return; // nothing to do

  // Reset state a little more frequently, minimal cost, avoid bugs.
  m_molecule->clearCubes();
  m_molecule->clearMeshes();
  m_cube = nullptr;
  m_mesh1 = nullptr;
  m_mesh2 = nullptr;
  m_molecule->emitChanged(Molecule::Atoms | Molecule::Added);
  bool connectSlots = false;

  // set up QtConcurrent calculators for Gaussian or Slater basis sets
  if (dynamic_cast<GaussianSet*>(m_basis)) {
    if (!m_gaussianConcurrent) {
      m_gaussianConcurrent = new GaussianSetConcurrent(this);
      connectSlots = true;
    }
    m_gaussianConcurrent->setMolecule(m_molecule);
  } else {
    if (!m_slaterConcurrent) {
      m_slaterConcurrent = new SlaterSetConcurrent(this);
      connectSlots = true;
    }
    m_slaterConcurrent->setMolecule(m_molecule);
  }

  // TODO: Check to see if this cube or surface has already been computed
  if (!m_progressDialog) {
    m_progressDialog = new QProgressDialog(qobject_cast<QWidget*>(parent()));
    m_progressDialog->setCancelButtonText(nullptr);
    m_progressDialog->setWindowModality(Qt::NonModal);
    connectSlots = true;
  }

  if (!m_cube)
    m_cube = m_molecule->addCube();

  Type type = m_dialog->surfaceType();
  int index = m_dialog->surfaceIndex();
  m_isoValue = m_dialog->isosurfaceValue();
  m_cube->setLimits(*m_molecule, m_dialog->resolution(), 5.0);

  QString progressText;
  if (type == ElectronDensity) {
    progressText = tr("Calculating electron density");
    m_cube->setName("Electron Denisty");
    if (dynamic_cast<GaussianSet*>(m_basis)) {
      m_gaussianConcurrent->calculateElectronDensity(m_cube);
    } else {
      m_slaterConcurrent->calculateElectronDensity(m_cube);
    }
  }

  else if (type == MolecularOrbital) {
    progressText = tr("Calculating molecular orbital %L1").arg(index);
    m_cube->setName("Molecular Orbital " + std::to_string(index + 1));
    if (dynamic_cast<GaussianSet*>(m_basis)) {
      m_gaussianConcurrent->calculateMolecularOrbital(m_cube, index,
                                                      m_dialog->beta());
    } else {
      m_slaterConcurrent->calculateMolecularOrbital(m_cube, index);
    }
  }

  // Set up the progress dialog.
  if (dynamic_cast<GaussianSet*>(m_basis)) {
    m_progressDialog->setWindowTitle(progressText);
    m_progressDialog->setRange(
      m_gaussianConcurrent->watcher().progressMinimum(),
      m_gaussianConcurrent->watcher().progressMaximum());
    m_progressDialog->setValue(m_gaussianConcurrent->watcher().progressValue());
    m_progressDialog->show();

    if (connectSlots) {
      connect(&m_gaussianConcurrent->watcher(),
              SIGNAL(progressValueChanged(int)), m_progressDialog,
              SLOT(setValue(int)));
      connect(&m_gaussianConcurrent->watcher(),
              SIGNAL(progressRangeChanged(int, int)), m_progressDialog,
              SLOT(setRange(int, int)));
      connect(m_gaussianConcurrent, SIGNAL(finished()), SLOT(displayMesh()));
    }
  } else {
    // slaters
    m_progressDialog->setWindowTitle(progressText);
    m_progressDialog->setRange(m_slaterConcurrent->watcher().progressMinimum(),
                               m_slaterConcurrent->watcher().progressMaximum());
    m_progressDialog->setValue(m_slaterConcurrent->watcher().progressValue());
    m_progressDialog->show();

    connect(&m_slaterConcurrent->watcher(), SIGNAL(progressValueChanged(int)),
            m_progressDialog, SLOT(setValue(int)));
    connect(&m_slaterConcurrent->watcher(),
            SIGNAL(progressRangeChanged(int, int)), m_progressDialog,
            SLOT(setRange(int, int)));
    connect(m_slaterConcurrent, SIGNAL(finished()), SLOT(displayMesh()));
  }
}

void Surfaces::calculateCube()
{
  if (!m_dialog || m_cubes.size() == 0)
    return;

  // check bounds
  m_cube = m_cubes[m_dialog->surfaceIndex()];
  m_isoValue = m_dialog->isosurfaceValue();
  displayMesh();
}

void Surfaces::stepChanged(int n)
{
  if (!m_molecule || !m_basis)
    return;

  qDebug() << "\n\t==== Step changed to" << n << "====";
  auto g = dynamic_cast<GaussianSet*>(m_basis);
  if (g) {
    g->setActiveSetStep(n - 1);
    m_molecule->clearCubes();
    m_molecule->clearMeshes();
    m_cube = nullptr;
    m_mesh1 = nullptr;
    m_mesh2 = nullptr;
    m_molecule->emitChanged(Molecule::Atoms | Molecule::Added);
  }
}

void Surfaces::displayMesh()
{
  if (!m_cube)
    return;

  if (!m_mesh1)
    m_mesh1 = m_molecule->addMesh();
  if (!m_meshGenerator1) {
    m_meshGenerator1 = new QtGui::MeshGenerator;
    connect(m_meshGenerator1, SIGNAL(finished()), SLOT(meshFinished()));
  }
  m_meshGenerator1->initialize(m_cube, m_mesh1, -m_isoValue);

  // TODO - only do this if we're generating an orbital
  //    and we need two meshes
  //   How do we know? - likely ask the cube if it's an MO?
  if (!m_mesh2)
    m_mesh2 = m_molecule->addMesh();
  if (!m_meshGenerator2) {
    m_meshGenerator2 = new QtGui::MeshGenerator;
    connect(m_meshGenerator2, SIGNAL(finished()), SLOT(meshFinished()));
  }
  m_meshGenerator2->initialize(m_cube, m_mesh2, m_isoValue, true);

  // Start the mesh generation - this needs an improved mutex with a read lock
  // to function as expected. Write locks are exclusive, read locks can have
  // many read locks but no write lock.
  m_meshGenerator1->start();
  m_meshGenerator2->start();

  // Track how many meshes are left to show.
  m_meshesLeft = 2;
}

void Surfaces::meshFinished()
{
  --m_meshesLeft;
  if (m_meshesLeft == 0) {
    if (m_recordingMovie) {
      // Move to the next frame.
      qDebug() << "Let's get to the next frame...";
      m_molecule->emitChanged(QtGui::Molecule::Added);
      movieFrame();
    } else {
      m_dialog->reenableCalculateButton();
      m_molecule->emitChanged(QtGui::Molecule::Added);
    }
  }
  // TODO: enable the mesh display type
}

void Surfaces::recordMovie()
{
  QString baseFileName;
  if (m_molecule)
    baseFileName = m_molecule->data("fileName").toString().c_str();

  QString selectedFilter = tr("Movie AVI (*.avi)");
  QString baseName = QFileDialog::getSaveFileName(
    qobject_cast<QWidget*>(parent()), tr("Export Movie"), "",
    tr("Movie MP4 (*.mp4);;Movie AVI (*.avi);;GIF (*.gif)"), &selectedFilter);

  if (baseName.isEmpty()) {
    m_dialog->enableRecord();
    return;
  }

  QFileInfo fileInfo(baseName);
  if (!fileInfo.suffix().isEmpty())
    baseName = fileInfo.absolutePath() + "/" + fileInfo.baseName();

  m_baseFileName = baseName;
  m_numberLength = static_cast<int>(
    ceil(log10(static_cast<float>(m_molecule->coordinate3dCount()) + 1)));

  m_recordingMovie = true;
  m_currentFrame = 1;
  m_frameCount = m_molecule->coordinate3dCount();

  // Figure out the save type, and work accordingly...
  if (selectedFilter == tr("GIF (*.gif)")) {
    d->gwaviWriter = nullptr;
    d->gifWriter = new GifWriter;
    GifBegin(d->gifWriter, (baseName + ".gif").toLatin1().data(), 800, 600,
             100 / 4);
  } else if (selectedFilter == tr("Movie AVI (*.avi)")) {
    d->gifWriter = nullptr;
    d->gwaviWriter = gwavi_open((baseName + ".avi").toLatin1().data(), 800, 600,
                                "MJPG", 4, nullptr);
  } else {
    d->gwaviWriter = nullptr;
    d->gifWriter = nullptr;
  }

  stepChanged(m_currentFrame);
  m_dialog->setStep(m_currentFrame);
  calculateSurface();
}

void Surfaces::movieFrame()
{
  // Not ideal, need to let things update asynchronously, complete, before we
  // capture the frame. When appropriate move to the next frame or complete.
  QCoreApplication::sendPostedEvents();
  QCoreApplication::processEvents();

  auto glWidget = QtOpenGL::ActiveObjects::instance().activeGLWidget();
  if (!glWidget) {
    QMessageBox::warning(qobject_cast<QWidget*>(parent()), tr("Avogadro"),
                         "Couldn't find the active render widget, failing.");
    m_recordingMovie = false;
    m_dialog->enableRecord();
    return;
  }
  glWidget->resize(800 / glWidget->devicePixelRatio(),
                   600 / glWidget->devicePixelRatio());
  QImage exportImage;
  glWidget->raise();
  glWidget->repaint();
  if (QOpenGLFramebufferObject::hasOpenGLFramebufferObjects()) {
    exportImage = glWidget->grabFramebuffer();
  } else {
    QPixmap pixmap = QPixmap::grabWindow(glWidget->winId());
    exportImage = pixmap.toImage();
  }

  if (d->gifWriter) {
    int pixelCount = exportImage.width() * exportImage.height();
    uint8_t* imageData = new uint8_t[pixelCount * 4];
    int imageIndex = 0;
    for (int j = 0; j < exportImage.height(); ++j) {
      for (int k = 0; k < exportImage.width(); ++k) {
        QColor color = exportImage.pixel(k, j);
        imageData[imageIndex] = static_cast<uint8_t>(color.red());
        imageData[imageIndex + 1] = static_cast<uint8_t>(color.green());
        imageData[imageIndex + 2] = static_cast<uint8_t>(color.blue());
        imageData[imageIndex + 3] = static_cast<uint8_t>(color.alpha());
        imageIndex += 4;
      }
    }
    GifWriteFrame(d->gifWriter, imageData, 800, 600, 100 / 4);
    delete[] imageData;
  } else if (d->gwaviWriter) {
    QByteArray ba;
    QBuffer buffer(&ba);
    buffer.open(QIODevice::WriteOnly);
    exportImage.save(&buffer, "JPG");
    if (gwavi_add_frame(
          d->gwaviWriter,
          reinterpret_cast<const unsigned char*>(buffer.data().data()),
          buffer.size()) == -1) {
      QMessageBox::warning(qobject_cast<QWidget*>(parent()), tr("Avogadro"),
                           tr("Error: cannot add frame to video."));
    }
  } else {
    QString fileName = QString::number(m_currentFrame);
    while (fileName.length() < m_numberLength)
      fileName.prepend('0');
    fileName.prepend(m_baseFileName);
    fileName.append(".png");
    qDebug() << "Writing to" << fileName;

    if (!exportImage.save(fileName)) {
      QMessageBox::warning(qobject_cast<QWidget*>(parent()), tr("Avogadro"),
                           tr("Cannot save file %1.").arg(fileName));
      return;
    }
  }

  // Increment current frame.
  ++m_currentFrame;
  if (m_currentFrame <= m_frameCount) {
    qDebug() << "Starting next frame...";
    stepChanged(m_currentFrame);
    m_dialog->setStep(m_currentFrame);
    calculateSurface();
  } else {
    qDebug() << "We are done! Make some movies.";
    if (d->gifWriter) {
      GifEnd(d->gifWriter);
      delete d->gifWriter;
      d->gifWriter = nullptr;
    } else if (d->gwaviWriter) {
      gwavi_close(d->gwaviWriter);
      d->gwaviWriter = nullptr;
    } else {
      QProcess proc;
      QStringList args;
      args << "-y"
           << "-r" << QString::number(10) << "-i"
           << m_baseFileName + "%0" + QString::number(m_numberLength) + "d.png"
           << "-c:v"
           << "libx264"
           << "-r"
           << "30"
           << "-pix_fmt"
           << "yuv420p" << m_baseFileName + ".mp4";
      proc.execute("avconv", args);
    }
    /*
    args.clear();
    args << "-dispose"
         << "Background"
         << "-delay" << QString::number(100 / 10)
         << m_baseFileName + "%0" + QString::number(m_numberLength) + "d.png[0-"
    +
              QString::number(m_molecule->coordinate3dCount() - 1) + "]"
         << m_baseFileName + ".gif";
    proc.execute("convert", args);
    */

    m_recordingMovie = false;
    m_dialog->enableRecord();
  }
}

} // namespace QtPlugins
} // namespace Avogadro
