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

#define CAMERA_NEAR_DISTANCE 13.35 //Experimental number


namespace Avogadro {
namespace QtPlugins {

ResetView::ResetView(QObject* parent_) :
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

void ResetView::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void ResetView::setCamera(Rendering::Camera* camera)
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
    animationCamera(NULL, false);
    return true;
  }
  return false;
}

void ResetView::animationCamera(Eigen::Affine3f* goal, bool animate)
{
  if (goal == nullptr) {
    Eigen::Matrix3f linearGoal = Eigen::Matrix3f::Identity();
    goal = new Eigen::Affine3f(linearGoal);
    goal->pretranslate(-1.0f * CAMERA_NEAR_DISTANCE * Eigen::Vector3f::UnitZ());
  }

  if(animate) {

  }
  else {
    m_camera->setModelView(*goal);

  }
}

inline void getOBB(const Core::Array<Vector3>& mols, Vector3& centroid,
  Vector3& min, Vector3& mid, Vector3& max)
{
  centroid = Vector3::Zero();

  for (unsigned int i = 0; i < mols.size(); ++i)
    centroid += mols[i];

  centroid /= mols.size();
  Matrix3 covariance = Matrix3::Zero();

  for (unsigned int i = 0; i < mols.size(); ++i) {
    Vector3 adjusted = mols[i] - centroid;
    covariance += adjusted * adjusted.transpose();
  }

  Eigen::EigenSolver<Matrix3> solver = Eigen::EigenSolver<Matrix3>(covariance);
  Eigen::Matrix3cd vectors = solver.eigenvectors();

  if ((vectors.col(0).norm() < vectors.col(1).norm())
      && (vectors.col(0).norm() < vectors.col(2).norm())) {
    min = vectors.col(0).real();
    max = (vectors.col(1).norm() > vectors.col(2).norm())? vectors.col(1).real()
      : vectors.col(2).real();
    mid = (vectors.col(1).norm() > vectors.col(2).norm())? vectors.col(2).real()
      : vectors.col(1).real();
  }
  else if (vectors.col(1).norm() < vectors.col(2).norm()){
    min = vectors.col(1).real();
    max = (vectors.col(0).norm() > vectors.col(2).norm())? vectors.col(0).real()
      : vectors.col(2).real();
    mid = (vectors.col(0).norm() > vectors.col(2).norm())? vectors.col(2).real()
      : vectors.col(0).real();
  }
  else {
    min = vectors.col(2).real();
    max = (vectors.col(0).norm() > vectors.col(1).norm())? vectors.col(0).real()
      : vectors.col(1).real();
    mid = (vectors.col(0).norm() > vectors.col(1).norm())? vectors.col(1).real()
      : vectors.col(0).real();
  }
}

void ResetView::centerView()
{
  if (defaultChecks()) return;

  const Core::Array<Vector3> mols = m_molecule->atomPositions3d();
  Vector3 centroid, min, mid, max;
  getOBB(mols, centroid, min, mid, max );

  Eigen::Matrix3f linearGoal;

  linearGoal.row(0) = (max.normalized()).cast<float>();
  linearGoal.row(1) = (mid.normalized()).cast<float>();
  linearGoal.row(2) = (min.normalized()).cast<float>();
  // calculate the translation matrix
  Eigen::Affine3f *goal = new Eigen::Affine3f(linearGoal);
  goal->pretranslate(-1.0f * CAMERA_NEAR_DISTANCE * Eigen::Vector3f::UnitZ());

  animationCamera(goal);

  return;
}

void ResetView::alignToAxes()
{
  if (defaultChecks()) return;
  animationCamera(NULL);
}

} // namespace QtPlugins
} // namespace Avogadro
