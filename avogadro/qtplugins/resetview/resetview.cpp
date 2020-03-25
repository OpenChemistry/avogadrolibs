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

#include <unsupported/Eigen/MatrixFunctions>
#include <avogadro/rendering/camera.h>
#include <avogadro/qtgui/molecule.h>

#include <QtWidgets/QAction>
#include <QTimer>

#define CAMERA_NEAR_DISTANCE 13.35f //Experimental number


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
    animationCameraDefault(false);
    return true;
  }
  return false;
}

inline float getZDistance(const Eigen::Affine3f& projection, float x, Rendering::Projection perspective)
{
  if(perspective == Rendering::Projection::Perspective) {
    float fov = 2.0f*std::atan( 1.0f/projection(1,1) );
    //float aspect = projection(1,1) / projection(0,0);
    // tan (fov/2) = (x/2) / z -> z =  (x/2) / tan (fov/2)
    return std::max(CAMERA_NEAR_DISTANCE, (x/2.0f) / std::tan(fov/2.0f));
  }
  else {
    return 3.0f*CAMERA_NEAR_DISTANCE;
  }
}
inline void getBB(const Core::Array<Vector3>& mols, Vector3& min, Vector3& max)
{
  min = mols[0];
  max = mols[0];
  for (unsigned int i = 1; i < mols.size(); ++i) {
    min.x() = std::min(mols[i].x(), min.x());
    max.x() = std::max(mols[i].x(), max.x());

    min.y() = std::min(mols[i].y(), min.y());
    max.y() = std::max(mols[i].y(), max.y());

    min.z() = std::min(mols[i].z(), min.z());
    max.z() = std::max(mols[i].z(), max.z());
  }
}

void ResetView::animationCameraDefault(bool animate)
{
  const Core::Array<Vector3> mols = m_molecule->atomPositions3d();
  Vector3 min, max;

  getBB(mols,min, max);

  Eigen::Matrix3f linearGoal;
  linearGoal.row(0) = Vector3f::UnitX();
  linearGoal.row(1) = Vector3f::UnitY();
  linearGoal.row(2) = Vector3f::UnitZ();
  // calculate the translation matrix
  Eigen::Affine3f *goal = new Eigen::Affine3f(linearGoal);

  Vector3f mid = (max.cast<float>() + min.cast<float>())/2.0f;
  float d = getZDistance(m_camera->projection(),
                       max.x() - min.x(), m_camera->projectionType());

  Vector3f eye = -mid + (Vector3f::UnitZ() * -1.0f * d);
  goal->translate(eye);
  animationCamera(goal, animate);
}

void ResetView::animationCamera(Eigen::Affine3f* goal, bool animate)
{
  if(animate) {}
  else {
    m_camera->setModelView(*goal);
  }
}

// Calculate the oriented bounding box to get the most significand
// axis base and the centroid
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

  std::vector<Vector3> l {vectors.col(0).real(), vectors.col(1).real(), vectors.col(2).real()};
  for(int i = 0; i < 2; ++i) {
    int indexJ = 0;
    if(i == 0) max = l[indexJ];
    else mid = l[indexJ];

    for (int j = indexJ+1; j < 3; ++j){
      if(l[j].norm() > max.norm()) {
        indexJ = j;
        if(i == 0) max = l[indexJ];
        else mid = l[indexJ];
      }
    }
    std::vector<Vector3>::iterator itr = l.begin() + indexJ;
    l.erase(itr);
  }
  min = l[0];
}

void ResetView::centerView()
{
  if (defaultChecks()) return;

  const Core::Array<Vector3> mols = m_molecule->atomPositions3d();
  Vector3 centroid, min, mid, max;
  getOBB(mols, centroid, min, mid, max);

  Eigen::Matrix3f linearGoal;
  linearGoal.row(0) = (max.normalized()).cast<float>();
  linearGoal.row(1) = (mid.normalized()).cast<float>();
  linearGoal.row(2) = (min.normalized()).cast<float>();
  // calculate the translation matrix
  Eigen::Affine3f *goal = new Eigen::Affine3f(linearGoal);
  float d = getZDistance(m_camera->projection(),
                       max.norm(), m_camera->projectionType());
  Vector3f eye = (-centroid.cast<float>()) + (linearGoal.row(2).transpose() * -1.0f * d);
  goal->translate(eye);
  animationCamera(goal);
}

void ResetView::alignToAxes()
{
  if (defaultChecks()) return;
  animationCameraDefault();
}

} // namespace QtPlugins
} // namespace Avogadro
