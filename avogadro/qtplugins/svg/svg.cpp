/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "svg.h"

#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QSvgGenerator>
#include <QtWidgets/QAction>
#include <avogadro/qtopengl/glwidget.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/scene.h>
#include <iostream>
#include <string>

namespace Avogadro {
namespace QtPlugins {

const float SVG::DEFAULT_RADIUS = 35.0f;
const float SVG::DEFAULT_PEN_WIDTH_MOL = 1.0f;
const float SVG::DEFAULT_PEN_WIDTH_BOND = 4.0f;
const float SVG::DEFAULT_OFF_SET_PARALEL = 7.0f;
const float SVG::DEFAULT_IMAGE_PADDING = 1.0f;
const Vector3ub SVG::DEFAULT_BOND_COLOR = Vector3ub(125, 125, 125);

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

  // no need to create SVG when there are no atoms
  if (m_molecule->atomCount() == 0)
    return true;

  return false;
}

void SVG::setOptions()
{
  m_radius = DEFAULT_RADIUS;
  m_penWidthMol = DEFAULT_PEN_WIDTH_MOL;
  m_penWidthBond = DEFAULT_PEN_WIDTH_BOND;
  m_offSetParalel = DEFAULT_OFF_SET_PARALEL;
  m_ImagePadding = DEFAULT_IMAGE_PADDING;
  m_BondColor = DEFAULT_BOND_COLOR;
}

// calculate the camera frustrum
void SVG::calculateCamera()
{
  Eigen::Matrix4f m = (m_camera->projection() * m_camera->modelView()).matrix();

  m_frustrum = std::vector<Eigen::Vector4f>(6);
  // right
  m_frustrum[0] = Eigen::Vector4f(m(0, 3) + m(0, 0), m(1, 3) + m(1, 0),
                                  m(2, 3) + m(2, 0), m(3, 3) + m(3, 0));
  // left
  m_frustrum[1] = Eigen::Vector4f(m(0, 3) - m(0, 0), m(1, 3) - m(1, 0),
                                  m(2, 3) - m(2, 0), m(3, 3) - m(3, 0));
  // top
  m_frustrum[2] = Eigen::Vector4f(m(0, 3) - m(0, 1), m(1, 3) - m(1, 1),
                                  m(2, 3) - m(2, 1), m(3, 3) - m(3, 1));
  // bottom
  m_frustrum[3] = Eigen::Vector4f(m(0, 3) + m(0, 1), m(1, 3) + m(1, 1),
                                  m(2, 3) + m(2, 1), m(3, 3) + m(3, 1));
  // far
  m_frustrum[4] = Eigen::Vector4f(m(0, 2), m(1, 2), m(2, 2), m(3, 2));
  // near
  m_frustrum[5] = Eigen::Vector4f(m(0, 3) - m(0, 2), m(1, 3) - m(1, 2),
                                  m(2, 3) - m(2, 2), m(3, 3) - m(3, 2));
}

// conservative frustrum culling
bool SVG::frustrumCulling(const SVGAtom& atom)
{
  return true;
  for (const auto& p : m_frustrum) {
    Eigen::Vector4f pos_model;
    pos_model << atom.pos_model, 1.0f;
    if (p.dot(pos_model) + atom.radius <= 0)
      return true;
  }
  return false;
}

// transform view position to 2d SVG image
Eigen::Vector3f SVG::posToSVGImage(const SVGAtom& atom)
{
  Eigen::Vector3f result = m_camera->project(atom.pos_model);
  float scale = 1.0f + ((atom.pos_view - m_min).norm() / m_max.norm());
  float r_scale = 2.0f - (1.0f / atom.radius);

  result[1] = ((result[1] - (m_height / 2.0f)) * -1.0f) + (m_height / 2.0f);
  result[2] = m_radius * r_scale * scale;
  return result;
}

// get all model, view, image positions sort them and save id to vector index
void SVG::getPositions()
{
  m_atoms.clear();
  calculateCamera();
  m_max[0] = m_max[1] = m_max[2] = Eigen::Infinity;
  m_min[0] = m_min[1] = m_min[2] = Eigen::Infinity * -1.0f;

  const Core::Array<Vector3> atomPositions = m_molecule->atomPositions3d();
  for (unsigned int i = 0; i < atomPositions.size(); ++i) {
    Eigen::Vector3f pos =
      m_camera->modelView() * atomPositions[i].cast<float>();
    pos[1] *= -1.0f;
    SVGAtom atom(atomPositions[i].cast<float>(), pos, i,
                 m_molecule->bonds(i).size());
    m_atoms.push_back(atom);
    if (frustrumCulling(atom)) {
      for (unsigned int j = 0; j < 3; ++j) {
        if (m_min[j] > pos[j])
          m_min[j] = pos[j];
        if (m_max[j] < pos[j])
          m_max[j] = pos[j];
      }
    }
  }
  m_min[0] -= m_ImagePadding;
  m_min[1] -= m_ImagePadding;
  m_max[0] += m_ImagePadding;
  m_max[1] += m_ImagePadding;
  m_max -= m_min;
  std::sort(m_atoms.begin(), m_atoms.end(),
            [&](const SVGAtom& a, const SVGAtom& b) {
              // sort using the distance to the camera
              return a.pos_view.norm() > b.pos_view.norm();
            });
  int i = 0;
  for (auto& m : m_atoms) {
    m_idToindex[m.id] = i;
    m.pos_image = posToSVGImage(m);
    ++i;
  }
}

// paint all bondings only once
void SVG::paintBonds(QPainter& painter, const SVGAtom& atom, unsigned int i,
                     const NeighborListType& bonds)
{
  painter.setPen(QPen(QColor(m_BondColor[0], m_BondColor[1], m_BondColor[2]),
                      m_penWidthBond));
  for (auto it = bonds.begin(); it != bonds.end(); ++it) {
    unsigned int j = it->atom2().index();
    if (m_idToindex[j] == i) {
      j = it->atom1().index();
    }
    if (m_idToindex[j] <= i) {
      continue;
    }
    // calculate the inicial and final position, considering the atom middle
    // and the middle of the pen width
    auto mol_to = m_atoms[m_idToindex[j]].pos_image;
    Eigen::Vector2f from(atom.pos_image[0] - (m_penWidthBond / 2.0f),
                         atom.pos_image[1] - (m_penWidthBond / 2.0f));
    Eigen::Vector2f to(mol_to[0] - (m_penWidthBond / 2.0f),
                       mol_to[1] - (m_penWidthBond / 2.0f));

    float L = std::sqrt((from[0] - to[0]) * (from[0] - to[0]) +
                        (from[1] - to[1]) * (from[1] - to[1]));
    float offsetX = (to[1] - from[1]) / L;
    float offsetY = (from[0] - to[0]) / L;
    unsigned int order = int(it->order());
    // for each bound offset it following the orthogonal direction
    for (unsigned int o = 0; o < order; ++o) {
      // if there is only one bond, don't displace
      float x = 0, y = 0;
      if (order > 1) {
        x = (float(o) - (order / 2.0f)) * m_offSetParalel * offsetX;
        y = (float(o) - (order / 2.0f)) * m_offSetParalel * offsetY;
      }
      QLineF line(from[0] + x, from[1] + y, to[0] + x, to[1] + y);
      painter.drawLine(line);
    }
  }
}

void SVG::paintCore(QPainter& painter, const SVGAtom& atom)
{
  Vector3ub atom_color = m_molecule->color(atom.id);
  QColor color(atom_color[0], atom_color[1], atom_color[2]);
  painter.setPen(QPen(QColor(0, 0, 0), m_penWidthMol));
  painter.setBrush(color);
  painter.drawEllipse(atom.pos_image[0] - atom.pos_image[2] / 2.0f,
                      atom.pos_image[1] - atom.pos_image[2] / 2.0f,
                      atom.pos_image[2], atom.pos_image[2]);
}

void SVG::paintSVG(QPainter& painter)
{
  const Vector4ub background = m_scene->backgroundColor();
  QColor backgroundColor(background[0], background[1], background[2],
                         background[3]);
  painter.fillRect(QRect(0, 0, m_width, m_height), backgroundColor);
  getPositions();
  for (unsigned int i = 0; i < m_atoms.size(); ++i) {
    auto atom = m_atoms[i];
    const NeighborListType bonds = m_molecule->bonds(atom.id);
    if (frustrumCulling(atom)) {
      paintBonds(painter, atom, i, bonds);
      paintCore(painter, atom);
    }
  }
}

void SVG::render()
{
  setOptions();
  if (defaultChecks())
    return;
  QString filename = QFileDialog::getSaveFileName(
    qobject_cast<QWidget*>(parent()), tr("Save File"), QDir::homePath(),
    tr("SVG (*.svg)"));
  if (!filename.endsWith(".svg", Qt::CaseInsensitive))
    filename.append(".svg");

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
