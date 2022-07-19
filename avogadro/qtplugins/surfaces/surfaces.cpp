/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "surfaces.h"
#include "surfacedialog.h"

#include "tinycolormap.hpp"

#include "gaussiansetconcurrent.h"
#include "slatersetconcurrent.h"

// Header only, but duplicate symbols if included globally...
namespace {
#include <gif.h>
}

#include <gwavi.h>

#include <avogadro/calc/chargemanager.h>

#include <avogadro/core/color3f.h>
#include <avogadro/core/variant.h>
#include <avogadro/core/vector.h>

#include <avogadro/core/cube.h>
#include <avogadro/core/mesh.h>
#include <avogadro/core/neighborperceiver.h>
#include <avogadro/qtgui/meshgenerator.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwlayermanager.h>
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

#include <QtConcurrent/QtConcurrentMap>
#include <QtConcurrent/QtConcurrentRun>
#include <QtCore/QBuffer>
#include <QtCore/QCoreApplication>
#include <QtCore/QDebug>
#include <QtCore/QProcess>
#include <QtGui/QOpenGLFramebufferObject>
#include <QtWidgets/QAction>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressDialog>

using namespace tinycolormap;

namespace Avogadro::QtPlugins {

using Core::Array;
using Core::GaussianSet;
using Core::NeighborPerceiver;
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
  action->setText(tr("Create Surfaces…"));
  connect(action, SIGNAL(triggered()), SLOT(surfacesActivated()));
  connect(&m_displayMeshWatcher, SIGNAL(finished()), SLOT(displayMesh()));
  connect(&m_performEDTStepWatcher, SIGNAL(finished()), SLOT(performEDTStep()));
  
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
    for (auto & m_cube : m_cubes) {
      cubeNames << m_cube->name().c_str();
    }
    m_dialog->setupCubes(cubeNames);
  }
  m_dialog->setupSteps(m_molecule->coordinate3dCount());

  const auto identifiers = Calc::ChargeManager::instance().identifiersForMolecule(*m_molecule);
  std::set<std::pair<std::string, std::string>> chargeModels;
  for (const auto &identifier: identifiers)
    chargeModels.emplace(Calc::ChargeManager::instance().nameForModel(identifier), identifier);
  m_dialog->setupModels(chargeModels);

  m_dialog->show();
}

float Surfaces::resolution()
{
  if (!m_dialog->automaticResolution())
    return m_dialog->resolution();

  float r = 0.02 * powf(m_molecule->atomCount(), 1.0f / 3.0f);
  float minimum = 0.05;
  float maximum = 0.5;

  switch (m_dialog->surfaceType()) {
    case SolventExcluded:
      minimum = 0.1;
      break;
    default:
      ;
  }

  r = std::max(minimum, std::min(maximum, r));
  return r;
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

float inline square(float x) { return x * x; }

void Surfaces::calculateEDT()
{
  QFuture future = QtConcurrent::run([=]() {
    double probeRadius = 0.0;
    switch (m_dialog->surfaceType()) {
      case VanDerWaals:
          break;
      case SolventAccessible:
      case SolventExcluded:
          probeRadius = 1.4;
          break;
    }

    // first, make a list of all atom positions and radii
    Array<Vector3> atomPositions = m_molecule->atomPositions3d();
    auto *atoms = new std::vector<std::pair<Vector3, double>>();
    double max_radius = probeRadius;
    QtGui::RWLayerManager layerManager;
    for (size_t i = 0; i < m_molecule->atomCount(); i++) {
      if (!layerManager.visible(m_molecule->layer(i)))
        continue;
      auto radius = Core::Elements::radiusVDW(m_molecule->atomicNumber(i)) + probeRadius;
      atoms->emplace_back(atomPositions[i], radius);
      if (radius > max_radius)
        max_radius = radius;
    }

    double padding = max_radius + probeRadius;
    m_cube->setLimits(*m_molecule, resolution(), padding);
    m_cube->fill(-1.0);

    const float res = resolution();
    const Vector3 min = m_cube->min();
    const float mdist = probeRadius;

    // then, for each atom, set cubes around it up to a certain radius
    QFuture innerFuture = QtConcurrent::map(*atoms, [=](std::pair<Vector3, double> &in) {
      double startPosX = in.first(0) - in.second;
      double endPosX = in.first(0) + in.second;
      int startIndexX = (startPosX - min(0)) / res;
      int endIndexX = (endPosX - min(0)) / res + 1;
      for (int indexX = startIndexX; indexX < endIndexX; indexX++) {
        double posX = indexX * res + min(0);
        double radiusXsq = square(in.second) - square(posX - in.first(0));
        if (radiusXsq < 0.0)
          continue;
        double radiusX = sqrt(radiusXsq);
        double startPosY = in.first(1) - radiusX;
        double endPosY = in.first(1) + radiusX;
        int startIndexY = (startPosY - min(1)) / res;
        int endIndexY = (endPosY - min(1)) / res + 1;
        for (int indexY = startIndexY; indexY < endIndexY; indexY++) {
          double posY = indexY * res + min(1);
          double lengthXYsq = square(radiusX) - square(posY - in.first(1));
          if (lengthXYsq < 0.0)
            continue;
          double lengthXY = sqrt(lengthXYsq);
          double startPosZ = in.first(2) - lengthXY;
          double endPosZ = in.first(2) + lengthXY;
          int startIndexZ = (startPosZ - min(2)) / res;
          int endIndexZ = (endPosZ - min(2)) / res + 1;
          m_cube->fillStripe(indexX, indexY, startIndexZ, endIndexZ - 1, 1.0f);
        }
      }
    });
    
    innerFuture.waitForFinished();
  });
  
  // SolventExcluded requires an extra pass
  if (m_dialog->surfaceType() == SolventExcluded) {
    m_performEDTStepWatcher.setFuture(future);
  } else {
    m_displayMeshWatcher.setFuture(future);
  }
}

void Surfaces::performEDTStep()
{
  QFuture future = QtConcurrent::run([=]() {
    const double probeRadius = 1.4;
    const double scaledProbeRadius = probeRadius / resolution();
    
    // make a list of all "outside" cubes in contact with an "inside" cube
    // these are the only ones that can be "nearest" to an "inside" cube
    Array<Vector3> relativePositions;
    // also make a list of all "inside" cubes
    auto *insideIndices = new std::vector<Vector3i>;
    Vector3i size = m_cube->dimensions();
    relativePositions.reserve(size(0) * size(1) * 4); // O(n^2)
    insideIndices->reserve(size(0) * size(1) * size(2)); // O(n^3)
    for (int z = 0; z < size(2); z++) {
      int zp = std::max(z - 1, 0);
      int zn = std::min(z + 1, size(2) - 1);
      for (int y = 0; y < size(1); y++) {
        int yp = std::max(y - 1, 0);
        int yn = std::min(y + 1, size(1) - 1);
        for (int x = 0; x < size(0); x++) {
          if (m_cube->value(x, y, z) > 0.0) {
            insideIndices->emplace_back(x, y, z);
            continue;
          }
          int xp = std::max(x - 1, 0);
          int xn = std::min(x + 1, size(0) - 1);
          if (m_cube->value(xp, y, z) > 0.0
            || m_cube->value(xn, y, z) > 0.0
            || m_cube->value(x, yp, z) > 0.0
            || m_cube->value(x, yn, z) > 0.0
            || m_cube->value(x, y, zp) > 0.0
            || m_cube->value(x, y, zn) > 0.0
          ) {
            relativePositions.push_back(Vector3(x, y, z));
          }
        }
      }
    }
    
    // pass the list to a NeighborPerceiver so it's faster to look up
    NeighborPerceiver perceiver(relativePositions, scaledProbeRadius);
    
    // now, exclude all "inside" cubes too close to any "outside" cube
    thread_local Array<Index> *neighbors = nullptr;
    QFuture innerFuture = QtConcurrent::map(*insideIndices, [=](Vector3i &in) {
      Vector3 pos = in.cast<double>();
      if (neighbors == nullptr)
        neighbors = new Array<Index>;
      perceiver.getNeighborsInclusiveInPlace(*neighbors, pos);
      for (Index neighbor: *neighbors) {
        const Vector3 &npos = relativePositions[neighbor];
        float distance = (npos - pos).norm();
        if (distance <= scaledProbeRadius) {
          m_cube->setValue(in(0), in(1), in(2), -1.0f);
          break;
        }
      }
    });
    
    innerFuture.waitForFinished();
  });
  
  m_displayMeshWatcher.setFuture(future);
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
  m_cube->setLimits(*m_molecule, resolution(), 5.0);

  QString progressText;
  if (type == ElectronDensity) {
    progressText = tr("Calculating electron density");
    m_cube->setName("Electron Density");
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

  qDebug() << " running displayMesh";

  m_smoothingPasses = m_dialog->smoothingPassesValue();

  if (!m_mesh1)
    m_mesh1 = m_molecule->addMesh();
  if (!m_meshGenerator1) {
    m_meshGenerator1 = new QtGui::MeshGenerator;
    connect(m_meshGenerator1, SIGNAL(finished()), SLOT(meshFinished()));
  }
  m_meshGenerator1->initialize(m_cube, m_mesh1, -m_isoValue, m_smoothingPasses);

  // TODO - only do this if we're generating an orbital
  //    and we need two meshes
  //   How do we know? - likely ask the cube if it's an MO?
  if (!m_mesh2)
    m_mesh2 = m_molecule->addMesh();
  if (!m_meshGenerator2) {
    m_meshGenerator2 = new QtGui::MeshGenerator;
    connect(m_meshGenerator2, SIGNAL(finished()), SLOT(meshFinished()));
  }
  m_meshGenerator2->initialize(m_cube, m_mesh2, m_isoValue, m_smoothingPasses, true);

  // Start the mesh generation - this needs an improved mutex with a read lock
  // to function as expected. Write locks are exclusive, read locks can have
  // many read locks but no write lock.
  m_meshGenerator1->start();
  m_meshGenerator2->start();

  // Track how many meshes are left to show.
  m_meshesLeft = 2;
}

Core::Color3f Surfaces::chargeGradient(double value, double clamp, ColormapType colormap) const
{
  // okay, typically color scales have blue at the bottom, red at the top.
  // so we need to invert, so blue is positive charge, red is negative charge.
  // we also need to scale the color to the range of the charge.
  double scaledValue = value / clamp; // from -1 to 1.0
  double scaledValue2 =
    1.0 - ((scaledValue + 1.0) / 2.0); // from 0 to 1.0 red to blue

  auto color = tinycolormap::GetColor(scaledValue2, colormap);
  Core::Color3f r(float(color.r()), color.g(), color.b());

  return r;
}

ColormapType Surfaces::getColormapFromString(const QString& name) const
{
  // Just do all of them, even though we won't use them all
  if (name == tr("Parula", "colormap"))
    return ColormapType::Parula;
  else if (name == tr("Heat", "colormap"))
    return ColormapType::Heat;
  else if (name == tr("Hot", "colormap"))
    return ColormapType::Hot;
  else if (name == tr("Gray", "colormap"))
    return ColormapType::Gray;
  else if (name == tr("Magma", "colormap"))
    return ColormapType::Magma;
  else if (name == tr("Inferno", "colormap"))
    return ColormapType::Inferno;
  else if (name == tr("Plasma", "colormap"))
    return ColormapType::Plasma;
  else if (name == tr("Viridis", "colormap"))
    return ColormapType::Viridis;
  else if (name == tr("Cividis", "colormap"))
    return ColormapType::Cividis;
  else if (name == tr("Spectral", "colormap"))
    return ColormapType::Spectral;
  else if (name == tr("Coolwarm", "colormap"))
    return ColormapType::Coolwarm;
  else if (name == tr("Balance", "colormap"))
    return ColormapType::Balance;
  else if (name == tr("Blue-DarkRed", "colormap"))
    return ColormapType::BlueDkRed;
  else if (name == tr("Turbo", "colormap"))
    return ColormapType::Turbo;

  return ColormapType::Turbo;
}

void Surfaces::colorMeshByPotential()
{
  const auto model = m_dialog->colorModel().toStdString();
  const auto colormap = getColormapFromString(m_dialog->colormapName());
  
  const auto positionsf = m_mesh1->vertices();
  Core::Array<Vector3> positions(positionsf.size());
  std::transform(positionsf.begin(), positionsf.end(), positions.begin(),
    [](const Vector3f &pos) { return pos.cast<double>(); }
  );
  const auto potentials = Calc::ChargeManager::instance().potentials(model, *m_molecule, positions);
  
  double minPotential = *std::min_element(potentials.begin(), potentials.end());
  double maxPotential = *std::max_element(potentials.begin(), potentials.end());
  double clamp = std::max(std::abs(minPotential), std::abs(minPotential));
  
  Core::Array<Core::Color3f> colors(positions.size());
  for (size_t i = 0; i < potentials.size(); i++)
    colors[i] = chargeGradient(potentials[i], clamp, colormap);
  
  m_mesh1->setColors(colors);
}

void Surfaces::colorMesh()
{
  switch (m_dialog->colorProperty()) {
    case None:
      break;
    case ByElectrostaticPotential:
      colorMeshByPotential();
      break;
  }
}

void Surfaces::meshFinished()
{
  --m_meshesLeft;
  if (m_meshesLeft == 0) {
    colorMesh();
    if (m_recordingMovie) {
      // Move to the next frame.
      qDebug() << "Let's get to the next frame…";
      m_molecule->emitChanged(QtGui::Molecule::Added);
      movieFrame();
    } else {
      m_dialog->reenableCalculateButton();

      qDebug() << " mesh finished";

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
    auto* imageData = new uint8_t[pixelCount * 4];
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
    qDebug() << "Starting next frame…";
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

} // namespace Avogadro
