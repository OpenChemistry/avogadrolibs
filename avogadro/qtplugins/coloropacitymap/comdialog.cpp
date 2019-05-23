/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#include "comdialog.h"

#include "ui_comdialog.h"

#include <avogadro/core/cube.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtopengl/activeobjects.h>
#include <avogadro/vtk/vtkglwidget.h>

namespace Avogadro {
namespace QtPlugins {

using QtOpenGL::ActiveObjects;
using VTK::vtkGLWidget;

ComDialog::ComDialog(QWidget* p, Qt::WindowFlags f)
  : QDialog(p, f), m_ui(new Ui::ComDialog)
{
  m_ui->setupUi(this);
  connect(m_ui->enableVolumeRendering, SIGNAL(stateChanged(int)),
          SLOT(enableVolume(int)));
  connect(m_ui->enableIsosurface, SIGNAL(stateChanged(int)),
          SLOT(enableIsosurface(int)));
  connect(m_ui->isoValue, SIGNAL(valueChanged(double)),
          SLOT(setIsoValue(double)));
  connect(m_ui->opacity, SIGNAL(valueChanged(double)),
          SLOT(setOpacity(double)));
}

ComDialog::~ComDialog()
{
  delete m_ui;
}

HistogramWidget* ComDialog::histogramWidget()
{
  return m_ui->histogramWidget;
}

void ComDialog::setMolecule(QtGui::Molecule* mol)
{
  if (m_molecule == mol || !mol)
    return;
  m_molecule = mol;
  // Figure out which cubes are available.
  m_ui->cubesComboBox->clear();
  for (Index i = 0; i < mol->cubeCount(); ++i) {
    m_ui->cubesComboBox->addItem(QString(mol->cube(i)->name().c_str()));
  }
}

void ComDialog::enableVolume(int enable)
{
  auto w = ActiveObjects::instance().activeWidget();
  auto vtkgl = qobject_cast<vtkGLWidget*>(w);
  if (vtkgl) {
    vtkgl->renderVolume(enable == 0 ? false : true);
    emit renderNeeded();
  }
}

void ComDialog::enableIsosurface(int enable)
{
  auto w = ActiveObjects::instance().activeWidget();
  auto vtkgl = qobject_cast<vtkGLWidget*>(w);
  if (vtkgl) {
    vtkgl->renderIsosurface(enable == 0 ? false : true);
    emit renderNeeded();
  }
}

void ComDialog::setIsoValue(double value)
{
  auto w = ActiveObjects::instance().activeWidget();
  auto vtkgl = qobject_cast<vtkGLWidget*>(w);
  if (vtkgl) {
    vtkgl->setIsoValue(value);
    emit renderNeeded();
  }
}

void ComDialog::setOpacity(double value)
{
  auto w = ActiveObjects::instance().activeWidget();
  auto vtkgl = qobject_cast<vtkGLWidget*>(w);
  if (vtkgl) {
    vtkgl->setOpacity(value);
    emit renderNeeded();
  }
}

} // namespace QtPlugins
} // namespace Avogadro