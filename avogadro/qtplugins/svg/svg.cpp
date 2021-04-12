#include "svg.h"

#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QSvgGenerator>
#include <QtWidgets/QAction>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtopengl/glwidget.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/scene.h>
#include <iostream>
#include <string>
#include <vector>

namespace Avogadro {
namespace QtPlugins {

typedef Avogadro::Core::Array<Avogadro::Core::Bond> NeighborListType;

const float SVG::RADIUS = 25;
const float SVG::PEN_WIDTH_MOL = 1;
const float SVG::PEN_WIDTH_BOND = 4;
const float SVG::OFF_SET_PARALEL = 7;

SVG::SVG(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_molecule(nullptr),
    m_scene(nullptr), m_camera(nullptr), m_action(new QAction(tr("SVG"), this))
{
  connect(m_action, SIGNAL(triggered()), SLOT(render()));
}

SVG::~SVG() {}

QList<QAction*> SVG::actions() const
{
  QList<QAction*> result;
  return result << m_action;
}

QStringList SVG::menuPath(QAction*) const
{
  return QStringList() << tr("&File") << tr("&Export");
}

void SVG::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void SVG::setScene(Rendering::Scene* scene)
{
  m_scene = scene;
}

void SVG::setCamera(Rendering::Camera* camera)
{
  m_camera = camera;
}

bool SVG::defaultChecks()
{
  if ((m_molecule == nullptr) || (m_camera == nullptr))
    return true;

  // Check for 3D coordinates - it's useless to consider the camera otherwise
  if (m_molecule->atomPositions3d().size() != m_molecule->atomCount())
    return true;

  // no need to animate when there are no atoms
  if (m_molecule->atomCount() == 0)
    return true;

  return false;
}

bool sortByDistance(Eigen::Vector3f i, Eigen::Vector3f j)
{
  return i[2] < j[2];
}

Eigen::Vector3f SVG::possToImage(const Vector3f& mol, float r)
{
  if (r <= 0) {
    r = 1;
  }
  Eigen::Vector3f poss = mol - m_min;
  poss =
    Eigen::Vector3f(poss[0] / m_max[0] * m_width, poss[1] / m_max[1] * m_height,
                    SVG::RADIUS * r * (poss[2] / m_max[2]));
  return poss;
}

void SVG::paintSVG(QPainter& painter)
{
  const Vector4ub background = m_scene->backgroundColor();
  QColor backgroundColor(background[0], background[1], background[2],
                         background[3]);
  painter.fillRect(QRect(0, 0, m_width, m_height), backgroundColor);

  const Eigen::Affine3f modelView = m_camera->modelView();
  const Eigen::Affine3f projection = m_camera->projection();
  const Core::Array<Vector3> mols = m_molecule->atomPositions3d();
  Eigen::Vector3f dummy = projection * modelView * mols[0].cast<float>();
  dummy[1] *= -1.0f;
  dummy[2] *= -1.0f;
  m_min = dummy;
  m_max = dummy;

  std::vector<Eigen::Vector3f> mols_d;
  for (unsigned int i = 0; i < mols.size(); ++i) {
    Eigen::Vector3f poss = projection * modelView * mols[i].cast<float>();
    poss[1] *= -1.0f;
    poss[2] *= -1.0f;
    mols_d.push_back(poss);
    if (m_min[2] > poss[2])
      m_min[2] = poss[2];
    if (m_max[2] < poss[2])
      m_max[2] = poss[2];
  }

  m_min[0] = m_min[1] = -15.0f;
  m_max[0] = m_max[1] = 15.0f;
  m_max -= m_min;

  for (unsigned int i = 0; i < mols_d.size(); ++i) {
    const NeighborListType bonds = m_molecule->bonds(i);
    Eigen::Vector3f poss = possToImage(mols_d[i], bonds.size());
    painter.setPen(QPen(QColor(125, 125, 125), PEN_WIDTH_BOND));
    for (NeighborListType::const_iterator it = bonds.begin(); it != bonds.end();
         ++it) {
      unsigned int j = it->atom2().index();
      if (j <= i) {
        continue;
      }

      Eigen::Vector3f poss_to =
        possToImage(mols_d[j], m_molecule->bonds(j).size());
      // calculate the inicial and final position, considering the circle midle
      // point and the middle of the pen width
      Eigen::Vector2f from(poss[0] + (poss[2] / 2.0f) - (PEN_WIDTH_BOND / 2.0f),
                           poss[1] + (poss[2] / 2.0f) -
                             (PEN_WIDTH_BOND / 2.0f));
      Eigen::Vector2f to(
        poss_to[0] + (poss_to[2] / 2.0f) - (PEN_WIDTH_BOND / 2.0f),
        poss_to[1] + (poss_to[2] / 2.0f) - (PEN_WIDTH_BOND / 2.0f));

      float L = std::sqrt((from[0] - to[0]) * (from[0] - to[0]) +
                          (from[1] - to[1]) * (from[1] - to[1]));
      float offsetX = (to[1] - from[1]) / L;
      float offsetY = (from[0] - to[0]) / L;
      unsigned int order = int(it->order());
      // for each bound offset it following the orthogonal direction
      for (unsigned int o = 0; o < order; ++o) {
        float x = 0, y = 0;
        if (order > 1) {
          x = (float(o) - (order / 2.0f)) * OFF_SET_PARALEL * offsetX;
          y = (float(o) - (order / 2.0f)) * OFF_SET_PARALEL * offsetY;
        }
        QLineF line(from[0] + x, from[1] + y, to[0] + x, to[1] + y);
        painter.drawLine(line);
      }
    }

    Vector3ub color_mol = m_molecule->color(i);
    QColor color(color_mol[0], color_mol[1], color_mol[2]);
    painter.setPen(QPen(QColor(0, 0, 0), PEN_WIDTH_MOL));
    painter.setBrush(color);

    painter.drawEllipse(poss[0], poss[1], poss[2], poss[2]);
  }
}

void SVG::render()
{
  if (defaultChecks())
    return;
  QString filename = QFileDialog::getSaveFileName(
    qobject_cast<QWidget*>(parent()), tr("Save File"), QDir::homePath(),
    tr("SVG (*.svg)"));
  QFile file(filename);
  if (!file.open(QIODevice::WriteOnly))
    return;

  m_width = m_camera->width();
  m_height = m_camera->height();

  QSvgGenerator generator;
  generator.setFileName(filename);
  generator.setSize(QSize(m_width, m_height));
  generator.setViewBox(QRect(0, 0, m_width, m_height));

  QPainter painter;
  painter.begin(&generator);
  paintSVG(painter);
  painter.end();
}

} // namespace QtPlugins
} // namespace Avogadro
