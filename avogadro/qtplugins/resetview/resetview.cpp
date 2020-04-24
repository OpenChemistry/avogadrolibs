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

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtopengl/glwidget.h>
#include <avogadro/rendering/camera.h>

#include <QTimer>
#include <QtWidgets/QAction>
#include <QtWidgets/QOpenGLWidget>

#define CAMERA_NEAR_DISTANCE 13.35f // Experimental number

namespace Avogadro {
namespace QtPlugins {

const float ResetView::DELTA_TIME = 100.0f / 3.0f; // 33.3 ms ~ 30 fps
const int ResetView::TOTAL_FRAMES = 25;            // ~1 sec

ResetView::ResetView(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_),
    m_centerAction(new QAction(tr("Center"), this)),
    m_viewToAxesAction(new QAction(tr("Align View to Axes"), this))
{
  connect(m_centerAction, SIGNAL(triggered()), SLOT(centerView()));
  connect(m_viewToAxesAction, SIGNAL(triggered()), SLOT(alignToAxes()));
}

ResetView::~ResetView() {}

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

void ResetView::setActiveWidget(QWidget* widget)
{
  if (widget != nullptr) {
    m_glWidget = widget;
    connect(this, SIGNAL(updateRequested()), m_glWidget, SLOT(requestUpdate()));
  }
}

bool ResetView::defaultChecks()
{
  if (m_molecule == nullptr || m_camera == nullptr)
    return true;

  // Check for 3D coordinates - it's useless to consider the camera otherwise
  if (m_molecule->atomPositions3d().size() != m_molecule->atomCount())
    return true;

  // no need to animate when there are no atoms
  if (m_molecule->atomCount() == 0) {
    animationCameraDefault(false);
    return true;
  }
  return false;
}

inline float getZDistance(const Eigen::Affine3f& projection, float x,
                          Rendering::Projection perspective)
{
  if (perspective == Rendering::Projection::Perspective) {
    float fov = 2.0f * std::atan(1.0f / projection(1, 1));
    // float aspect = projection(1,1) / projection(0,0);
    // tan (fov/2) = (x/2) / z -> z =  (x/2) / tan (fov/2)
    return std::max(CAMERA_NEAR_DISTANCE, (x / 2.0f) / std::tan(fov / 2.0f));
  } else {
    return 3.0f * CAMERA_NEAR_DISTANCE;
  }
}
inline void getBB(const Core::Array<Vector3>& mols, Vector3& min, Vector3& max)
{
  if (mols.size() > 0) {
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
  } else {
    min = max = Vector3(0, 0, 0);
  }
} // namespace QtPlugins

void ResetView::animationCameraDefault(bool animate)
{
  Eigen::Matrix3f linearGoal;
  linearGoal.row(0) = Vector3f::UnitX();
  linearGoal.row(1) = Vector3f::UnitY();
  linearGoal.row(2) = Vector3f::UnitZ();
  // calculate the translation matrix
  Eigen::Affine3f goal = Eigen::Affine3f(linearGoal);

  const Core::Array<Vector3> mols = m_molecule->atomPositions3d();
  Vector3 min, max;
  getBB(mols, min, max);
  Vector3f mid = (max.cast<float>() + min.cast<float>()) / 2.0f;
  float d = getZDistance(m_camera->projection(), max.x() - min.x(),
                         m_camera->projectionType());

  Vector3f eye = -mid + (Vector3f::UnitZ() * -1.0f * d);
  goal.translate(eye);
  animationCamera(goal, animate);
}

void ResetView::animationCamera(const Eigen::Affine3f& goal, bool animate)
{
  if (animate) {
    Matrix3f rot_aux = goal.rotation();
    Vector3f posGoal = goal.translation();
    Eigen::Quaternionf rotGoal = Eigen::Quaternionf(rot_aux);

    Eigen::Affine3f start = m_camera->modelView();

    rot_aux = start.rotation();
    Vector3f posStart = start.translation();
    Eigen::Quaternionf rotStart = Eigen::Quaternionf(rot_aux);

    for (int frame = 0; frame < ResetView::TOTAL_FRAMES; ++frame) {
      Eigen::Affine3f interpolation;
      float alpha = frame / float(ResetView::TOTAL_FRAMES);
      interpolation.fromPositionOrientationScale(
        ((1.0f - alpha) * posStart) + (alpha * posGoal),
        rotStart.slerp(alpha, rotGoal), Vector3f(1.0f, 1.0f, 1.0f));

      float time = frame * ResetView::DELTA_TIME;
      QTimer::singleShot(time, this, [this, interpolation]() {
        m_camera->setModelView(interpolation);
        emit updateRequested();
      });
    }

    float time = ResetView::TOTAL_FRAMES * ResetView::DELTA_TIME;
    QTimer::singleShot(time, this, [this, goal]() {
      m_camera->setModelView(goal);
      emit updateRequested();
    });

  } else {
    m_camera->setModelView(goal);
    emit updateRequested();
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

  std::vector<Vector3> l{ vectors.col(0).real(), vectors.col(1).real(),
                          vectors.col(2).real() };
  max = l[0];
  mid = l[1];
  min = l[2];
}

void ResetView::centerView()
{
  if (defaultChecks())
    return;

  const Core::Array<Vector3> mols = m_molecule->atomPositions3d();
  Vector3 centroid, min, mid, max;
  getOBB(mols, centroid, min, mid, max);

  Eigen::Matrix3f linearGoal;
  linearGoal.row(0) = (max.normalized()).cast<float>(); // x
  linearGoal.row(1) = (mid.normalized()).cast<float>(); // y
  linearGoal.row(2) = (min.normalized()).cast<float>(); // z
  // calculate the translation matrix
  Eigen::Affine3f goal = Eigen::Affine3f(linearGoal);

  // eigen return the eigenvectors normalized, but we need a non-normalized
  getBB(mols, min, max);
  float d = getZDistance(m_camera->projection(), max.x() - min.x(),
                         m_camera->projectionType());
  Vector3f eye =
    (-centroid.cast<float>()) + (linearGoal.row(2).transpose() * -1.0f * d);
  goal.translate(eye);
  animationCamera(goal);
}

void ResetView::alignToAxes()
{
  if (defaultChecks())
    return;
  animationCameraDefault();
}

} // namespace QtPlugins
} // namespace Avogadro
