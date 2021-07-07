/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "cartoons.h"

#include <QtWidgets/QCheckBox>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>
#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>
#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/rendering/beziergeometry.h>
#include <avogadro/rendering/bsplinegeometry.h>
#include <avogadro/rendering/cartoongeometry.h>
#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>

#include <functional>
#include <list>
#include <utility>
#include <vector>

#include <iostream>

namespace Avogadro {
namespace QtPlugins {

using Core::AtomicNumber;
using Core::Elements;
using Core::Molecule;
using Rendering::BezierGeometry;
using Rendering::BSplineGeometry;
using Rendering::Cartoon;
using Rendering::CylinderGeometry;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::SphereGeometry;
using std::list;
using std::map;
using std::pair;
using std::reference_wrapper;
using std::vector;

struct BackboneResidue
{
  BackboneResidue() {}
  BackboneResidue(const Matrix3f& f, const Vector3f p, const Vector3ub& c1,
                  const Vector3ub& c2, const size_t& g)
    : frenet(f), pos(p), color1(c1), color2(c2), group(g)
  {}
  Matrix3f frenet;
  Vector3f pos;
  Vector3ub color1;
  Vector3ub color2;
  size_t group;
};

typedef list<BackboneResidue> AtomsPairList;

Cartoons::Cartoons(QObject* parent)
  : ScenePlugin(parent), m_group(nullptr), m_setupWidget(nullptr),
    m_enabled(false), m_showBackbone(false), m_showTrace(false),
    m_showTube(false), m_showRibbon(false), m_showRope(false),
    m_showCartoon(true)
{}

Cartoons::~Cartoons()
{
  if (m_setupWidget)
    m_setupWidget->deleteLater();
}

Matrix3f makeFrenet(const Eigen::Vector3f& ca, const Eigen::Vector3f& h,
                    const Eigen::Vector3f& nextCa, bool fliped)
{
  // calculate the frenet trihedron from direction between this point and
  // next, and the hidrogen bond
  Vector3f dirY;
  if (fliped) {
    dirY = (nextCa - ca).normalized();
  } else {
    dirY = (ca - nextCa).normalized();
  }
  Vector3f dirX = (h - ca).normalized();
  Vector3f dirZ = dirY.cross(dirX);
  dirX = dirZ.cross(dirY);

  Matrix3f linear;
  linear.col(0) = dirX;
  linear.col(1) = dirY;
  linear.col(2) = dirZ;
  linear.normalize();
  return linear;
}

map<size_t, AtomsPairList> getBackboneByResidues(const Molecule& molecule)
{
  const auto& graph = molecule.graph();
  map<size_t, AtomsPairList> result;

  map<size_t, BackboneResidue> previousCA;
  for (const auto& residue : molecule.residues()) {
    if (!residue.isHeterogen()) {
      Core::Atom caAtom = residue.getAtomByName("CA");
      Core::Atom oAtom = residue.getAtomByName("O");
      if (caAtom.isValid() && oAtom.isValid()) {
        // get the group ID and check if it's initialized in the map
        size_t group = graph.getConnectedID(caAtom.index());
        if (result.find(group) == result.end()) {
          result[group] = AtomsPairList();
        }

        Matrix3f frenet;
        Vector3f ca = caAtom.position3d().cast<float>();
        Vector3f o = oAtom.position3d().cast<float>();
        Vector3ub color2;
        if (previousCA.find(group) == previousCA.end()) {
          frenet = Matrix3f::Zero();
          frenet.col(0) = o;
          color2 = caAtom.color();
        } else {
          auto previous = previousCA[group];
          auto nextCa = previous.pos;
          auto previousO = previous.frenet.col(0);
          if (result[group].size() == 1) {
            result[group].begin()->frenet =
              makeFrenet(nextCa, previousO, ca, false);
            previousO = result[group].begin()->frenet.col(0);
          }

          if (o.dot(previousO) <= 0.0f) {
            o = -1.0f * o;
          }

          color2 = previous.color1;
          frenet = makeFrenet(ca, o, nextCa, true);
        }

        auto backBone =
          BackboneResidue(frenet, ca, caAtom.color(), color2, group);
        previousCA[group] = backBone;
        result[group].push_back(backBone);
      }
    }
  }
  return result;
}

map<size_t, AtomsPairList> getBackboneManually(const Molecule& molecule)
{
  // manual filter
  map<size_t, AtomsPairList> result;
  return result;
}

void renderBackbone(const AtomsPairList& backbone, const Molecule& molecule,
                    Rendering::GroupNode& node, float radius)
{
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  SphereGeometry* spheres = new SphereGeometry;
  spheres->identifier().molecule = reinterpret_cast<const void*>(&molecule);
  spheres->identifier().type = Rendering::AtomType;
  geometry->addDrawable(spheres);

  CylinderGeometry* cylinders = new CylinderGeometry;
  cylinders->identifier().molecule = &molecule;
  cylinders->identifier().type = Rendering::BondType;
  geometry->addDrawable(cylinders);

  Index i = 0;
  for (AtomsPairList::const_iterator it = backbone.begin();
       it != backbone.end(); ++it) {
    const auto& bone = *it;
    const Vector3f& pos = bone.pos;
    spheres->addSphere(pos, bone.color1, radius);
    if (std::next(it) != backbone.end()) {
      const auto& nextBone = *std::next(it);
      const Vector3f& pos2 = nextBone.pos;
      cylinders->addCylinder(pos, pos2, radius, bone.color1, bone.color2,
                             bone.group);
    }
    ++i;
  }
}

void renderRope(const AtomsPairList& backbone, const Molecule& molecule,
                Rendering::GroupNode& node, float radius, size_t id)
{
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  BezierGeometry* bezier = new BezierGeometry;
  bezier->identifier().molecule = &molecule;
  bezier->identifier().type = Rendering::BondType;
  geometry->addDrawable(bezier);

  for (const auto& bone : backbone) {
    bezier->addPoint(bone.frenet, bone.pos, bone.color1, radius, bone.group);
  }
}

void renderTube(const AtomsPairList& backbone, const Molecule& molecule,
                Rendering::GroupNode& node, float radius, size_t id)
{
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  BSplineGeometry* bezier = new BSplineGeometry;
  bezier->identifier().molecule = &molecule;
  bezier->identifier().type = Rendering::BondType;
  geometry->addDrawable(bezier);

  for (const auto& bone : backbone) {
    bezier->addPoint(bone.frenet, bone.pos, bone.color1, radius, bone.group);
  }
}

void renderCartoon(const AtomsPairList& backbone, const Molecule& molecule,
                   Rendering::GroupNode& node, float radius, size_t id)
{
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  Cartoon* cartoon = new Cartoon;
  cartoon->identifier().molecule = &molecule;
  cartoon->identifier().type = Rendering::BondType;
  geometry->addDrawable(cartoon);

  for (const auto& bone : backbone) {
    cartoon->addPoint(bone.frenet, bone.pos, bone.color1, radius, bone.group);
  }
}

void Cartoons::process(const Molecule& molecule, Rendering::GroupNode& node)
{
  if (m_showBackbone || m_showTrace || m_showTube || m_showRibbon ||
      m_showCartoon || m_showRope) {
    map<size_t, AtomsPairList> alphaAndHydrogens;
    if (molecule.residues().size() > 0) {
      alphaAndHydrogens = getBackboneByResidues(molecule);
    }
    if (alphaAndHydrogens.size() == 0) {
      alphaAndHydrogens = getBackboneManually(molecule);
    }
    size_t i = 0;
    for (const auto& group : alphaAndHydrogens) {
      const auto& alphaAndHydrogen = group.second;
      m_group = &node;
      if (m_showBackbone) {
        renderBackbone(alphaAndHydrogen, molecule, node, 0.1f);
      }
      if (m_showTrace) {
        renderTube(alphaAndHydrogen, molecule, node, -0.15f, i);
      }
      if (m_showTube) {
        renderTube(alphaAndHydrogen, molecule, node, 0.15f, i);
      }
      if (m_showRibbon) {
        renderCartoon(alphaAndHydrogen, molecule, node,
                      -1.0f * Cartoon::ELIPSE_RATIO, i);
      }
      if (m_showCartoon) {
        renderCartoon(alphaAndHydrogen, molecule, node, 1.0f, i);
      }
      if (m_showRope) {
        renderRope(alphaAndHydrogen, molecule, node, 1.0f, i);
      }
      ++i;
    }
  }
}

void Cartoons::processEditable(const QtGui::RWMolecule& molecule,
                               Rendering::GroupNode& node)
{}

bool Cartoons::isEnabled() const
{
  return m_enabled;
}

void Cartoons::setEnabled(bool enable)
{
  m_enabled = enable;
}

QWidget* Cartoons::setupWidget()
{
  if (!m_setupWidget) {
    m_setupWidget = new QWidget(qobject_cast<QWidget*>(parent()));
    QVBoxLayout* v = new QVBoxLayout;
    const char* boxesText[] = { "Backbone", "Trace",   "Tube",
                                "Ribbon",   "Cartoon", "Rope" };
    vector<reference_wrapper<bool>> boxesBools = { m_showBackbone, m_showTrace,
                                                   m_showTube,     m_showRibbon,
                                                   m_showCartoon,  m_showRope };
    m_jumpTable[0] = &Cartoons::showBackbone;
    m_jumpTable[1] = &Cartoons::showTrace;
    m_jumpTable[2] = &Cartoons::showTube;
    m_jumpTable[3] = &Cartoons::showRibbon;
    m_jumpTable[4] = &Cartoons::showCartoon;
    m_jumpTable[5] = &Cartoons::showRope;
    for (size_t i = 0; i < 6; ++i) {
      QCheckBox* check = new QCheckBox(tr(boxesText[i]));
      check->setChecked(boxesBools[i]);
      connect(check, &QCheckBox::clicked, this, m_jumpTable[i]);
      v->addWidget(check);
    }

    m_setupWidget->setLayout(v);
  }
  return m_setupWidget;
}

void Cartoons::showBackbone(bool show)
{
  if (show != m_showBackbone) {
    m_showBackbone = show;
    emit drawablesChanged();
  }
}

void Cartoons::showTrace(bool show)
{
  if (show != m_showTrace) {
    m_showTrace = show;
    emit drawablesChanged();
  }
}

void Cartoons::showTube(bool show)
{
  if (show != m_showTube) {
    m_showTube = show;
    emit drawablesChanged();
  }
}

void Cartoons::showRibbon(bool show)
{
  if (show != m_showRibbon) {
    m_showRibbon = show;
    emit drawablesChanged();
  }
}

void Cartoons::showCartoon(bool show)
{
  if (show != m_showCartoon) {
    m_showCartoon = show;
    emit drawablesChanged();
  }
}

void Cartoons::showRope(bool show)
{
  if (show != m_showRope) {
    m_showRope = show;
    emit drawablesChanged();
  }
}

} // namespace QtPlugins
} // namespace Avogadro
