/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012-13 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "resetview.h"

#include <avogadro/rendering/camera.h>
#include <avogadro/qtgui/molecule.h>

#include <QtWidgets/QAction>

namespace Avogadro {
namespace QtPlugins {

ResetView::ResetView(QObject *parent_) :
  Avogadro::QtGui::ExtensionPlugin(parent_),
  m_centerAction(new QAction(tr("Center"), this)),
  m_viewToAxesAction(new QAction(tr("Align View to Axes"), this))
{
  connect(m_centerAction, SIGNAL(triggered()), SLOT(centerView()));
  connect(m_viewToAxesAction, SIGNAL(triggered()), SLOT(alignToAxes()));
}

ResetView::~ResetView()
{
}

QList<QAction*> ResetView::actions() const
{
  QList<QAction*> result;
  return result << m_centerAction << m_viewToAxesAction;
}

QStringList ResetView::menuPath(QAction*) const
{
  return QStringList() << tr("&View");
}

void ResetView::setMolecule(QtGui::Molecule *mol)
{
  m_molecule = mol;
}

void ResetView::setCamera(Rendering::Camera *camera)
{
  m_camera = camera;
}

void ResetView::centerView()
{
  if (!m_molecule || m_camera)
    return;

  // Check for 3D coordinates - it's useless to consider the camera otherwise
  if (m_molecule->atomPositions3d().size() != m_molecule->atomCount())
    return;

  // no need to animate when there are no atoms
  if(m_molecule->atomCount() == 0)  {
    m_camera->translate( Eigen::Vector3d( 0.0, 0.0, -20.0 ) );
    return;
  }

  Matrix3d linearGoal;
  linearGoal.row(2) = d->glWidget->normalVector();
  linearGoal.row(0) = linearGoal.row(2).unitOrthogonal();
  linearGoal.row(1) = linearGoal.row(2).cross(linearGoal.row(0));

  // calculate the translation matrix
  Transform3d goal(linearGoal);

  goal.pretranslate(- 3.0 * (d->glWidget->radius() + CAMERA_NEAR_DISTANCE) * Vector3d::UnitZ());

  m_camera->setModelView(goal);
  return;
}

void ResetView::alignToAxes()
{
  if (!m_molecule || m_camera)
    return;

  // Check for 3D coordinates - it's useless to consider the camera otherwise
  if (m_molecule->atomPositions3d().size() != m_molecule->atomCount())
    return;
}

} // namespace QtPlugins
} // namespace Avogadro
