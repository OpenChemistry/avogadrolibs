#include "newquantumoutput.h"

#include "newsurfacedialog.h"
#include "gaussiansetconcurrent.h"
#include "slatersetconcurrent.h"

#include <avogadro/core/variant.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/core/cube.h>
#include <avogadro/core/mesh.h>
#include <avogadro/qtgui/meshgenerator.h>

#include <avogadro/core/basisset.h>
#include <avogadro/core/gaussiansettools.h>

#include <avogadro/io/fileformatmanager.h>
#include <avogadro/quantumio/gamessus.h>
#include <avogadro/quantumio/gaussianfchk.h>
#include <avogadro/quantumio/gaussiancube.h>
#include <avogadro/quantumio/molden.h>
#include <avogadro/quantumio/mopacaux.h>

#include <QtCore/QDebug>
#include <QtWidgets/QAction>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QProgressDialog>

namespace Avogadro {
namespace QtPlugins {

using Core::GaussianSet;
using Core::Cube;

NewQuantumOutput::NewQuantumOutput(QObject *p) :
  ExtensionPlugin(p),
  m_progressDialog(NULL),
  m_molecule(NULL),
  m_basis(NULL),
  m_concurrent(NULL),
  m_concurrent2(NULL),
  m_cube(NULL),
  m_mesh1(NULL),
  m_mesh2(NULL),
  m_meshGenerator1(NULL),
  m_meshGenerator2(NULL),
  m_dialog(NULL)
{
  QAction *action = new QAction(this);
  action->setEnabled(false);
  action->setText(tr("Calculate electronic surfaces..."));
  connect(action, SIGNAL(triggered()), SLOT(newSurfacesActivated()));
  m_actions.push_back(action);

  // Register our quantum file format.
  Io::FileFormatManager::registerFormat(new QuantumIO::GAMESSUSOutput);
  Io::FileFormatManager::registerFormat(new QuantumIO::GaussianFchk);
  Io::FileFormatManager::registerFormat(new QuantumIO::GaussianCube);
  Io::FileFormatManager::registerFormat(new QuantumIO::MoldenFile);
  Io::FileFormatManager::registerFormat(new QuantumIO::MopacAux);
}

NewQuantumOutput::~NewQuantumOutput()
{
  delete m_cube;
}

void NewQuantumOutput::setMolecule(QtGui::Molecule *mol)
{
  if (mol->basisSet()) {
    m_basis = mol->basisSet();
    m_actions[0]->setEnabled(true);
  }
  else if (mol->cubes().size() != 0) {
    m_cubes = mol->cubes();
    m_actions[0]->setEnabled(true);
  }

  m_molecule = mol;
}

QList<QAction *> NewQuantumOutput::actions() const
{
  return m_actions;
}

QStringList NewQuantumOutput::menuPath(QAction *) const
{
  QStringList path;
  path << tr("&NewQuantum");
  return path;
}

void NewQuantumOutput::newSurfacesActivated()
{
  if (!m_basis && !m_cubes.size() > 0)
    return;

  if (!m_dialog) {
    m_dialog = new NewSurfaceDialog(qobject_cast<QWidget *>(parent()));
    connect(m_dialog, SIGNAL(calculateClickedSignal(int,float,float)),
            SLOT(calculateSurface(int,float,float)));
  }

  if (m_basis) {
    m_dialog->setupBasis(m_basis->electronCount(),
                         m_basis->molecularOrbitalCount());
  }
  else if (m_cubes.size() > 0) {
    m_dialog->setupCube(m_cubes.size());
  }

  m_dialog->show();
}

void calculateSurface(int index, float isosurfaceValue,
                      float resolutionStepSize)
{
  //Here, we want to calculate surface and store
}

}
}
