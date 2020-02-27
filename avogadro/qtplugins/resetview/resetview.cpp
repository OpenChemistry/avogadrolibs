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

bool ResetView::defaultChecks()
{
    if (m_molecule == nullptr || m_camera == nullptr)
      return true;

    // Check for 3D coordinates - it's useless to consider the camera otherwise
    if (m_molecule->atomPositions3d().size() != m_molecule->atomCount())
      return true;

    // no need to animate when there are no atoms
    if(m_molecule->atomCount() == 0)  {
      m_camera->translate( Eigen::Vector3f( 0.0, 0.0, -20.0 ) );
      return true;
    }
    return false;
}

void ResetView::animationCamera(Eigen::Affine3f& goal)
{
    m_camera->setModelView(goal);
}

void ResetView::centerView()
{
  if (defaultChecks()) return;

  Eigen::Matrix3f linearGoal;
  linearGoal.row(2) = Eigen::Vector3f( 0.0, 0.0, 1.0 );
  linearGoal.row(0) = linearGoal.row(2).unitOrthogonal();
  linearGoal.row(1) = linearGoal.row(2).cross(linearGoal.row(0));
  // calculate the translation matrix
  Eigen::Affine3f goal(linearGoal);
  goal.pretranslate(- 3.0 * (40 + CAMERA_NEAR_DISTANCE) * Eigen::Vector3f::UnitZ());

  animationCamera(goal);

  return;
}

void ResetView::alignToAxes()
{
      if (defaultChecks()) return;

      Eigen::Matrix3f linearGoal;
      linearGoal.row(2) = Eigen::Vector3f( 0.0, 0.0, 1.0 );
      linearGoal.row(0) = linearGoal.row(2).unitOrthogonal();
      linearGoal.row(1) = linearGoal.row(2).cross(linearGoal.row(0));
      // calculate the translation matrix
      Eigen::Affine3f goal(linearGoal);
      goal.pretranslate(- 3.0 * (20 + CAMERA_NEAR_DISTANCE) * Eigen::Vector3f::UnitZ());

      animationCamera(goal);
}

} // namespace QtPlugins
} // namespace Avogadro
