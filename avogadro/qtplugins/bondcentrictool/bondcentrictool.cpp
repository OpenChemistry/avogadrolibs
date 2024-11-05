/******************************************************************************
  This source file is part of the Avogadro project.

  Adapted from Avogadro 1.x with the following authors' permission:
  Copyright (C) 2007 by Shahzad Ali
  Copyright (C) 2007 by Ross Braithwaite
  Copyright (C) 2007 by James Bunt
  Copyright (C) 2007,2008 by Marcus D. Hanwell
  Copyright (C) 2006,2007 by Benoit Jacob

  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "bondcentrictool.h"

#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/rendering/arcsector.h>
#include <avogadro/rendering/arcstrip.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/linestripgeometry.h>
#include <avogadro/rendering/meshgeometry.h>
#include <avogadro/rendering/quad.h>
#include <avogadro/rendering/quadoutline.h>
#include <avogadro/rendering/textlabel3d.h>
#include <avogadro/rendering/textproperties.h>

#include <avogadro/core/array.h>
#include <avogadro/core/atom.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QAction>
#include <QIcon>
#include <QMouseEvent>

#include <Eigen/Geometry>

#include <cmath>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

namespace Avogadro::QtPlugins {

using Core::Array;
using QtGui::Molecule;
using QtGui::RWAtom;
using QtGui::RWBond;
using QtGui::RWMolecule;
using Rendering::ArcSector;
using Rendering::ArcStrip;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::Identifier;
using Rendering::LineStripGeometry;
using Rendering::MeshGeometry;
using Rendering::Quad;
using Rendering::QuadOutline;

namespace {
const std::string degreeString("°");
/// @todo Add wide character support to text renderer.
const std::string angstromString("Å");

// Lookup for coloring bond angles:
const Vector3ub& getColor(size_t i)
{
  static std::vector<Vector3ub> colors;
  if (colors.empty()) {
    colors.emplace_back(255, 64, 32);
    colors.emplace_back(64, 255, 32);
    colors.emplace_back(32, 64, 255);
    colors.emplace_back(255, 255, 32);
    colors.emplace_back(255, 32, 255);
    colors.emplace_back(32, 255, 255);
    colors.emplace_back(255, 128, 0);
    colors.emplace_back(128, 255, 0);
    colors.emplace_back(0, 255, 128);
    colors.emplace_back(0, 128, 255);
    colors.emplace_back(255, 0, 128);
    colors.emplace_back(128, 0, 255);
  }

  return colors[i % colors.size()];
}

// Returns unsigned, smallest angle between v1 and v2
inline float vectorAngleDegrees(const Vector3f& v1, const Vector3f& v2)
{
  const float crossProductNorm(v1.cross(v2).norm());
  const float dotProduct(v1.dot(v2));
  return std::atan2(crossProductNorm, dotProduct) * RAD_TO_DEG_F;
}

// Returns signed, smallest angle between v1 and v2. Sign is determined from a
// right hand rule around axis.
inline float vectorAngleDegrees(const Vector3f& v1, const Vector3f& v2,
                                const Vector3f& axis)
{
  const Vector3f crossProduct(v1.cross(v2));
  const float crossProductNorm(crossProduct.norm());
  const float dotProduct(v1.dot(v2));
  const float signDet(crossProduct.dot(axis));
  const float angle(std::atan2(crossProductNorm, dotProduct) * RAD_TO_DEG_F);
  return signDet > 0.f ? angle : -angle;
}

} // namespace

BondCentricTool::BondCentricTool(QObject* parent_)
  : QtGui::ToolPlugin(parent_), m_activateAction(new QAction(this)),
    m_molecule(nullptr), m_renderer(nullptr), m_moveState(IgnoreMove),
    m_planeSnapIncr(10.f), m_snapPlaneToBonds(true)
{
  m_activateAction->setText(tr("Bond-Centric Manipulation"));
  m_activateAction->setToolTip(
    tr("Bond Centric Manipulation Tool\n\n"
       "Left Mouse: \tClick and drag to rotate the view.\n"
       "Middle Mouse: \tClick and drag to zoom in or out.\n"
       "Right Mouse: \tClick and drag to move the view.\n"
       "Double-Click: \tReset the view.\n\n"
       "Left Click & Drag on a Bond to set the Manipulation Plane:\n"
       "Left Click & Drag one of the Atoms in the Bond to change the angle\n"
       "Right Click & Drag one of the Atoms in the Bond to change the length"));
  setIcon();
}

BondCentricTool::~BondCentricTool() {}

void BondCentricTool::setIcon(bool darkTheme)
{
  if (darkTheme)
    m_activateAction->setIcon(QIcon(":/icons/bondcentric_dark.svg"));
  else
    m_activateAction->setIcon(QIcon(":/icons/bondcentric_light.svg"));
}

QWidget* BondCentricTool::toolWidget() const
{
  return nullptr;
}

void BondCentricTool::setMolecule(QtGui::Molecule* mol)
{
  if (mol && mol->undoMolecule() != m_molecule) {
    m_molecule = mol->undoMolecule();
    reset();
  }
}

void BondCentricTool::setEditMolecule(QtGui::RWMolecule* mol)
{
  if (m_molecule != mol) {
    m_molecule = mol;
    reset();
  }
}

void BondCentricTool::setGLWidget(QtOpenGL::GLWidget*) {}

void BondCentricTool::setGLRenderer(Rendering::GLRenderer* ren)
{
  m_renderer = ren;
}

QUndoCommand* BondCentricTool::mousePressEvent(QMouseEvent* e)
{
  // Don't start a new operation if we're already working:
  if (m_moveState != IgnoreMove)
    return nullptr;

  Rendering::Identifier ident = m_renderer->hit(e->pos().x(), e->pos().y());

  // If no hits, return. Also ensure that the hit molecule is the one we expect.
  if (!ident.isValid() || ident.molecule != &m_molecule->molecule())
    return nullptr;

  // If the hit is a left click on a bond, make it the selected bond and map
  // mouse movements to the bond plane rotation.
  if (ident.type == Rendering::BondType && e->button() == Qt::LeftButton)
    return initRotatePlane(e, ident);

  // Return if selectedBond is not valid or the hit is not on a bond:
  if (!m_selectedBond.isValid() || ident.type != Rendering::AtomType)
    return nullptr;

  // Test if the atom is in the selected bond, or one bond removed.
  RWAtom clickedAtom = m_molecule->atom(ident.index);
  RWBond selectedBond = m_selectedBond.bond();
  bool atomIsInBond = bondContainsAtom(selectedBond, clickedAtom);
  bool atomIsNearBond = false;
  RWAtom anchorAtom;
  if (!atomIsInBond) {
    Array<RWBond> bonds = m_molecule->bonds(clickedAtom);
    for (auto& bond : bonds) {
      RWAtom atom = bond.getOtherAtom(clickedAtom);
      if (bondContainsAtom(selectedBond, atom)) {
        anchorAtom = atom;
        atomIsNearBond = true;
        break;
      }
    }
  }

  if (!atomIsInBond && !atomIsNearBond)
    return nullptr;

  if (m_molecule) {
    m_molecule->setInteractive(true);
  }

  // If the hit is a left click on an atom in the selected bond, prepare to
  // rotate the clicked bond around the other atom in the bond.
  if (atomIsInBond && e->button() == Qt::LeftButton)
    return initRotateBondedAtom(e, clickedAtom);

  // If the hit is a right click on an atom in the selected bond, prepare to
  // change the bond length.
  if (atomIsInBond && e->button() == Qt::RightButton)
    return initAdjustBondLength(e, clickedAtom);

  // Is the hit a left click on an atom bonded to an atom in selectedBond?
  if (atomIsNearBond &&
      (e->button() == Qt::LeftButton || e->button() == Qt::RightButton)) {
    return initRotateNeighborAtom(e, clickedAtom, anchorAtom);
  }

  return nullptr;
}

QUndoCommand* BondCentricTool::mouseDoubleClickEvent(QMouseEvent* e)
{
  if (m_selectedBond.isValid() && e->button() == Qt::LeftButton) {
    reset();
    emit drawablesChanged();
  }
  return nullptr;
}

QUndoCommand* BondCentricTool::mouseMoveEvent(QMouseEvent* e)
{
  if (m_moveState == IgnoreMove)
    return nullptr;

  QUndoCommand* result = nullptr;

  switch (m_moveState) {
    case RotatePlane:
      result = rotatePlane(e);
      break;
    case RotateBondedAtom:
      result = rotateBondedAtom(e);
      break;
    case AdjustBondLength:
      result = adjustBondLength(e);
      break;
    case RotateNeighborAtom:
      result = rotateNeighborAtom(e);
      break;
    default:
      break;
  }

  return result;
}

QUndoCommand* BondCentricTool::mouseReleaseEvent(QMouseEvent*)
{
  if (m_moveState != IgnoreMove) {
    reset(KeepBond);
    emit drawablesChanged();

    if (m_molecule) {
      m_molecule->setInteractive(false); // allow an undo now
    }
  }

  return nullptr;
}

void BondCentricTool::draw(Rendering::GroupNode& node)
{
  RWBond selectedBond = m_selectedBond.bond();

  if (!selectedBond.isValid())
    return;

  auto* geo = new GeometryNode;
  node.addChild(geo);

  switch (m_moveState) {
    default:
    case IgnoreMove:
    case RotatePlane:
      drawBondQuad(*geo, selectedBond);
      drawAtomBondAngles(*geo, selectedBond.atom1(), selectedBond);
      drawAtomBondAngles(*geo, selectedBond.atom2(), selectedBond);
      break;

    case RotateBondedAtom: {
      drawBondQuad(*geo, selectedBond);

      RWAtom otherAtom = selectedBond.getOtherAtom(m_clickedAtom.atom());
      if (otherAtom.isValid()) {
        drawAtomBondAngles(*geo, otherAtom, selectedBond);
      }

      break;
    }

    case AdjustBondLength:
      drawBondQuad(*geo, selectedBond);
      drawBondLengthLabel(*geo, selectedBond);
      break;

    case RotateNeighborAtom: {
      RWAtom clickedAtom = m_clickedAtom.atom();
      RWAtom anchorAtom = m_anchorAtom.atom();
      RWBond otherBond = m_molecule->bond(clickedAtom, anchorAtom);
      if (otherBond.isValid())
        drawBondAngle(*geo, selectedBond, otherBond);
      break;
    }
  }
}

void BondCentricTool::reset(BondCentricTool::ResetBondBehavior bond)
{
  if (bond == ResetBond)
    m_selectedBond.reset();

  m_clickedAtom.reset();
  m_anchorAtom.reset();
  m_moveState = IgnoreMove;
  m_clickedPoint = QPoint();
}

void BondCentricTool::initializeBondVectors()
{
  RWBond bond = m_selectedBond.bond();
  if (bond.isValid()) {
    m_bondVector = (bond.atom2().position3d().cast<float>() -
                    bond.atom1().position3d().cast<float>())
                     .normalized();
    m_planeNormalMouse = m_bondVector.unitOrthogonal();
  }
}

void BondCentricTool::updateBondVector()
{
  RWBond bond = m_selectedBond.bond();
  if (bond.isValid()) {
    m_bondVector = (bond.atom2().position3d().cast<float>() -
                    bond.atom1().position3d().cast<float>())
                     .normalized();
  }
}

QUndoCommand* BondCentricTool::initRotatePlane(
  QMouseEvent* e, const Rendering::Identifier& ident)
{
  RWBond selectedBond = m_molecule->bond(ident.index);
  // Get unique id:
  Index bondUniqueId = m_molecule->bondUniqueId(selectedBond);
  if (bondUniqueId == MaxIndex)
    return nullptr; // Something went horribly wrong.

  // Reset the bond vector/plane normal if the bond changed
  if (bondUniqueId != m_selectedBond.uniqueIdentifier()) {
    m_selectedBond =
      QtGui::RWMolecule::PersistentBondType(m_molecule, bondUniqueId);
    initializeBondVectors();
  }
  updatePlaneSnapAngles();
  updateSnappedPlaneNormal();
  if (!m_selectedBond.isValid())
    return nullptr;
  e->accept();
  m_moveState = RotatePlane;
  m_clickedPoint = e->pos();
  m_lastDragPoint = e->pos();
  emit drawablesChanged();
  return nullptr;
}

QUndoCommand* BondCentricTool::initRotateBondedAtom(
  QMouseEvent* e, const QtGui::RWAtom& clickedAtom)
{
  m_clickedAtom = RWMolecule::PersistentAtomType(clickedAtom);
  if (!m_clickedAtom.isValid())
    return nullptr;
  e->accept();
  m_moveState = RotateBondedAtom;
  m_clickedPoint = e->pos();
  m_lastDragPoint = e->pos();
  resetFragment();
  emit drawablesChanged();
  return nullptr;
}

QUndoCommand* BondCentricTool::initAdjustBondLength(
  QMouseEvent* e, const QtGui::RWAtom& clickedAtom)
{
  m_clickedAtom = RWMolecule::PersistentAtomType(clickedAtom);
  if (!m_clickedAtom.isValid())
    return nullptr;
  e->accept();
  m_moveState = AdjustBondLength;
  m_clickedPoint = e->pos();
  m_lastDragPoint = e->pos();
  resetFragment();
  emit drawablesChanged();
  return nullptr;
}

QUndoCommand* BondCentricTool::initRotateNeighborAtom(
  QMouseEvent* e, const QtGui::RWAtom& clickedAtom,
  const QtGui::RWAtom& anchorAtom)
{
  m_clickedAtom = RWMolecule::PersistentAtomType(clickedAtom);
  m_anchorAtom = RWMolecule::PersistentAtomType(anchorAtom);
  if (!m_clickedAtom.isValid() || !m_anchorAtom.isValid())
    return nullptr;
  e->accept();
  m_moveState = RotateNeighborAtom;
  m_clickedPoint = e->pos();
  m_lastDragPoint = e->pos();
  resetFragment();
  emit drawablesChanged();
  return nullptr;
}

QUndoCommand* BondCentricTool::rotatePlane(QMouseEvent* e)
{
  // The bond should be valid.
  const RWBond selectedBond = m_selectedBond.bond();
  if (!selectedBond.isValid())
    return nullptr;

  const QPoint deltaDrag = e->pos() - m_lastDragPoint;
  const Rendering::Camera& camera(m_renderer->camera());

  // Atomic position in world coordinates
  const Vector3 beginPos(selectedBond.atom1().position3d());
  const Vector3 endPos(selectedBond.atom2().position3d());

  // Various quantities in window coordinates.
  const Vector3f beginWin(camera.project(beginPos.cast<float>()));
  const Vector3f endWin(camera.project(endPos.cast<float>()));
  Vector3f bondVecWin(endWin - beginWin);
  bondVecWin.z() = 0.f;
  // Points into the viewing volume from camera:
  const Vector3f zAxisWin(0.f, 0.f, 1.f);
  // In plane of screen, orthogonal to bond:
  const Vector3f orthoWin(zAxisWin.cross(bondVecWin).normalized());
  const Vector3f dragWin(static_cast<float>(deltaDrag.x()),
                         static_cast<float>(deltaDrag.y()), 0.f);

  // Compute the rotation. Not quite sure what's going on here, this is just
  // ported from Avogadro 1. It doesn't seem right that rotation would be in
  // degrees (it's the result of a dot product) and I think the fact that the
  // DEG_TO_RAD conversion results in a useful angle is just a happy
  // coincidence. But it works quite well.
  const float rotation = dragWin.dot(orthoWin) / orthoWin.norm();
  const Eigen::AngleAxisf rotator(rotation * DEG_TO_RAD_F, m_bondVector);

  // Rotate
  m_planeNormalMouse = rotator * m_planeNormalMouse;
  updateSnappedPlaneNormal();
  emit drawablesChanged();

  m_lastDragPoint = e->pos();
  return nullptr;
}

QUndoCommand* BondCentricTool::rotateBondedAtom(QMouseEvent* e)
{
  // Ensure that the mouse has moved a reasonable amount:
  if ((m_lastDragPoint - e->pos()).manhattanLength() < 2)
    return nullptr;

  RWBond bond = m_selectedBond.bond();
  RWAtom clickedAtom = m_clickedAtom.atom();
  RWAtom centerAtom = bond.getOtherAtom(clickedAtom);

  // Sanity check:
  if (!bond.isValid() || !clickedAtom.isValid() || !centerAtom.isValid())
    return nullptr;

  // Compute the transformation:
  //   - Rotation axis is m_planeNormal
  //   - Rotation angle is:
  //       - magnitude is angle between initial click and current pos around
  //         center atom (performed in 2D).
  //       - sign is based on whether m_planeNormal is pointing into/out of the
  //         screen.
  const Rendering::Camera& camera(m_renderer->camera());

  // Get the window coordinates of the relevant points
  const Vector3f centerPos(centerAtom.position3d().cast<float>());
  const Vector3f centerWin(camera.project(centerPos));
  const Vector2f centerWin2(centerWin.head<2>());
  const Vector2f lastDragWin(
    static_cast<float>(m_lastDragPoint.x()),
    static_cast<float>(camera.height() - m_lastDragPoint.y()));
  const Vector2f dragWin(static_cast<float>(e->pos().x()),
                         static_cast<float>(camera.height() - e->pos().y()));

  // Compute the angle between last drag and current drag positions
  const Vector2f lastDragWinVec((lastDragWin - centerWin2).normalized());
  const Vector2f dragWinVec((dragWin - centerWin2).normalized());
  const float crossProductNorm(lastDragWinVec.x() * dragWinVec.y() -
                               lastDragWinVec.y() * dragWinVec.x());
  const float dotProduct(lastDragWinVec.dot(dragWinVec));
  const float angle(std::atan2(crossProductNorm, dotProduct));

  // Figure out if the sign needs to be reversed:
  const Vector3f centerPlusNormal(centerPos + m_planeNormal);
  const Vector3f centerPlusNormalWin(camera.project(centerPlusNormal));
  bool reverseSign = (centerPlusNormalWin.z() - centerWin.z()) >= 0;

  // Build transform
  m_transform.setIdentity();
  m_transform.translate(centerPos);
  m_transform.rotate(
    Eigen::AngleAxisf(reverseSign ? -angle : angle, m_planeNormal));
  m_transform.translate(-centerPos);

  // Build the fragment if needed:
  if (m_fragment.empty())
    buildFragment(bond, clickedAtom);

  // Perform transformation
  transformFragment();
  updateBondVector();
  m_molecule->emitChanged(Molecule::Modified | Molecule::Atoms);
  emit drawablesChanged();

  m_lastDragPoint = e->pos();
  return nullptr;
}

QUndoCommand* BondCentricTool::adjustBondLength(QMouseEvent* e)
{
  // Ensure that the mouse has moved a reasonable amount:
  if ((m_lastDragPoint - e->pos()).manhattanLength() < 2)
    return nullptr;

  RWBond selectedBond = m_selectedBond.bond();
  RWAtom clickedAtom = m_clickedAtom.atom();

  // Sanity check:
  if (!selectedBond.isValid() || !clickedAtom.isValid())
    return nullptr;

  const Rendering::Camera& camera(m_renderer->camera());
  RWAtom otherAtom = selectedBond.getOtherAtom(clickedAtom);

  const Vector2f curPosWin(static_cast<float>(e->pos().x()),
                           static_cast<float>(e->pos().y()));
  const Vector2f lastPosWin(static_cast<float>(m_lastDragPoint.x()),
                            static_cast<float>(m_lastDragPoint.y()));

  const Vector3f bond(clickedAtom.position3d().cast<float>() -
                      otherAtom.position3d().cast<float>());
  const Vector3f mouse(camera.unProject(curPosWin) -
                       camera.unProject(lastPosWin));

  const Vector3f displacement((mouse.dot(bond) / bond.squaredNorm()) * bond);

  // Build transform
  m_transform.setIdentity();
  m_transform.translate(displacement);

  // Build the fragment if needed:
  if (m_fragment.empty())
    buildFragment(selectedBond, clickedAtom);

  // Perform transformation
  transformFragment();
  m_molecule->emitChanged(QtGui::Molecule::Modified | QtGui::Molecule::Atoms);
  emit drawablesChanged();

  m_lastDragPoint = e->pos();
  return nullptr;
}

QUndoCommand* BondCentricTool::rotateNeighborAtom(QMouseEvent* e)
{
  // Ensure that the mouse has moved a reasonable amount:
  if ((m_lastDragPoint - e->pos()).manhattanLength() < 2)
    return nullptr;

  RWBond selectedBond = m_selectedBond.bond();
  // Atom that was clicked
  RWAtom clickedAtom = m_clickedAtom.atom();
  // Atom in selected bond also attached to clickedAtom
  RWAtom anchorAtom = m_anchorAtom.atom();
  // The "other" atom in selected bond
  RWAtom otherAtom = selectedBond.getOtherAtom(anchorAtom);

  // Sanity check:
  if (!selectedBond.isValid() || !anchorAtom.isValid() ||
      !otherAtom.isValid() || !clickedAtom.isValid()) {
    return nullptr;
  }

  const Rendering::Camera& camera(m_renderer->camera());

  // Compute the angle between last drag and current drag positions
  const Vector3f center(anchorAtom.position3d().cast<float>());
  const Vector3f centerProj(camera.project(center));
  const Vector2f centerWin(centerProj.head<2>());
  const Vector2f curWin(static_cast<float>(e->pos().x()),
                        static_cast<float>(camera.height() - e->pos().y()));
  const Vector2f lastWin(
    static_cast<float>(m_lastDragPoint.x()),
    static_cast<float>(camera.height() - m_lastDragPoint.y()));
  const Vector2f curVecWin((curWin - centerWin).normalized());
  const Vector2f lastVecWin((lastWin - centerWin).normalized());
  const float crossProductNorm(lastVecWin.x() * curVecWin.y() -
                               lastVecWin.y() * curVecWin.x());
  const float dotProduct(lastVecWin.dot(curVecWin));
  const float angle(std::atan2(crossProductNorm, dotProduct));

  // Figure out if the sign needs to be reversed:
  const Vector3f other(otherAtom.position3d().cast<float>());
  const Vector3f otherProj(camera.project(other));
  const bool reverseSign = otherProj.z() <= centerProj.z();

  // Axis of rotation
  const Vector3f axis((center - other).normalized());

  // Build transform
  m_transform.setIdentity();
  m_transform.translate(center);
  m_transform.rotate(Eigen::AngleAxisf(reverseSign ? -angle : angle, axis));
  m_transform.translate(-center);

  // Build the fragment if needed:
  if (m_fragment.empty())
    buildFragment(selectedBond, anchorAtom);

  // Perform transformation
  transformFragment();
  updateBondVector();
  m_molecule->emitChanged(QtGui::Molecule::Modified | QtGui::Molecule::Atoms);
  emit drawablesChanged();

  m_lastDragPoint = e->pos();

  return nullptr;
}

void BondCentricTool::drawBondQuad(Rendering::GeometryNode& node,
                                   const RWBond& bond) const
{
  const Vector3f atom1Pos(bond.atom1().position3d().cast<float>());
  const Vector3f atom2Pos(bond.atom2().position3d().cast<float>());
  Vector3f offset(m_bondVector.cross(m_planeNormal));

  const Vector3f v1(atom1Pos + offset);
  const Vector3f v2(atom2Pos + offset);
  const Vector3f v3(atom1Pos - offset);
  const Vector3f v4(atom2Pos - offset);

  Quad* quad = new Quad;
  node.addDrawable(quad);
  quad->setColor(Vector3ub(63, 127, 255));
  quad->setOpacity(127);
  quad->setRenderPass(Rendering::TranslucentPass);
  quad->setQuad(v1, v2, v3, v4);

  auto* quadOutline = new QuadOutline;
  node.addDrawable(quadOutline);
  quadOutline->setColor(Vector3ub(63, 127, 255));
  quadOutline->setRenderPass(Rendering::OpaquePass);
  quadOutline->setQuad(v1, v2, v3, v4, 1.f);

  // If the plane is rotating, show a hint for the unsnapped plane.
  if (m_moveState == RotatePlane) {
    Vector3f moffset(m_bondVector.cross(m_planeNormalMouse));

    const Vector3f mv1(atom1Pos + moffset);
    const Vector3f mv2(atom2Pos + moffset);
    const Vector3f mv3(atom1Pos - moffset);
    const Vector3f mv4(atom2Pos - moffset);

    auto* mouseQuadOutline = new QuadOutline;
    node.addDrawable(mouseQuadOutline);
    mouseQuadOutline->setColor(Vector3ub(255, 255, 255));
    mouseQuadOutline->setOpacity(127);
    mouseQuadOutline->setRenderPass(Rendering::TranslucentPass);
    mouseQuadOutline->setQuad(mv1, mv2, mv3, mv4, 1.f);
  }
}

void BondCentricTool::drawBondAngle(Rendering::GeometryNode& node,
                                    const QtGui::RWBond& selectedBond,
                                    const QtGui::RWBond& movingBond) const
{
  // Draw the selected bond quad as usual
  drawBondQuad(node, selectedBond);

  // Determine the atom shared between the bonds (atom1).
  RWAtom atom1;
  RWAtom atom2;
  if (selectedBond.atom1() == movingBond.atom1() ||
      selectedBond.atom2() == movingBond.atom1()) {
    atom1 = movingBond.atom1();
    atom2 = movingBond.atom2();
  } else if (selectedBond.atom1() == movingBond.atom2() ||
             selectedBond.atom2() == movingBond.atom2()) {
    atom1 = movingBond.atom2();
    atom2 = movingBond.atom1();
  }

  if (!atom1.isValid())
    return;

  // Add another quad in the plane normal to
  // m_bondVector.cross(movingBondVector)
  const Vector3f a1(atom1.position3d().cast<float>());
  const Vector3f a2(atom2.position3d().cast<float>());
  const Vector3f movingBondVector(a2 - a1);
  const Vector3f movingBondUnitVector(movingBondVector.normalized());
  // calculate a vector in the plane spanned by movingBondVector and
  // m_bondVector that is orthogonal to m_bondVector, then project
  // movingBondVector onto it. This is used to calculate the 'new' a2.
  const Vector3f movingBondNormal(m_bondVector.cross(movingBondUnitVector));
  const Vector3f newA2Direction(movingBondNormal.cross(m_bondVector));
  const Vector3f movingBondVectorProj(movingBondVector.dot(newA2Direction) *
                                      newA2Direction);
  const Vector3f newA2(a1 + movingBondVectorProj);
  const Vector3f& movingBondOffset(m_bondVector);
  const Vector3f v1(a1 + movingBondOffset);
  const Vector3f v2(newA2 + movingBondOffset);
  const Vector3f v3(a1 - movingBondOffset);
  const Vector3f v4(newA2 - movingBondOffset);

  Quad* quad = new Quad;
  node.addDrawable(quad);
  quad->setColor(Vector3ub(63, 127, 255));
  quad->setOpacity(127);
  quad->setRenderPass(Rendering::TranslucentPass);
  quad->setQuad(v1, v2, v3, v4);

  auto* quadOutline = new QuadOutline;
  node.addDrawable(quadOutline);
  quadOutline->setColor(Vector3ub(63, 127, 255));
  quadOutline->setRenderPass(Rendering::OpaquePass);
  quadOutline->setQuad(v1, v2, v3, v4, 1.f);

  // Add an arc and label to show a bit more info:
  const Vector3f selectedBondOffset(m_planeNormal.cross(m_bondVector));
  const float radius(movingBondVector.norm() * 0.75f);
  Vector3f startEdge(newA2Direction * radius);
  Vector3f normal(m_bondVector);
  float angle = vectorAngleDegrees(startEdge, selectedBondOffset, normal);
  float displayAngle = std::fabs(angle);

  auto* sect = new ArcSector;
  node.addDrawable(sect);
  sect->setColor(Vector3ub(255, 127, 63));
  sect->setOpacity(127);
  sect->setRenderPass(Rendering::TranslucentPass);
  sect->setArcSector(a1, startEdge, normal, angle, 5.f);

  auto* arc = new ArcStrip;
  node.addDrawable(arc);
  arc->setColor(Vector3ub(255, 127, 63));
  arc->setRenderPass(Rendering::OpaquePass);
  arc->setArc(a1, startEdge, normal, angle, 5.f, 1.f);

  const Vector3f& textPos(a1);

  auto* label = new Rendering::TextLabel3D;
  label->setText(tr("%L1°").arg(displayAngle, 5, 'f', 1).toStdString());
  label->setRenderPass(Rendering::Overlay3DPass);
  label->setAnchor(textPos);
  node.addDrawable(label);

  Rendering::TextProperties tprop;
  tprop.setAlign(Rendering::TextProperties::HCenter,
                 Rendering::TextProperties::VCenter);
  tprop.setFontFamily(Rendering::TextProperties::SansSerif);
  tprop.setColorRgb(255, 200, 64);
  label->setTextProperties(tprop);
}

void BondCentricTool::drawBondLengthLabel(Rendering::GeometryNode& node,
                                          const QtGui::RWBond& bond)
{
  const Vector3f startPos(bond.atom1().position3d().cast<float>());
  const Vector3f endPos(bond.atom2().position3d().cast<float>());
  const Vector3f bondCenter((startPos + endPos) * 0.5f);
  const Vector3f bondVector(endPos - startPos);

  auto* label = new Rendering::TextLabel3D;
  label->setText(tr("%L1 Å").arg(bondVector.norm(), 4, 'f', 2).toStdString());
  label->setRenderPass(Rendering::Overlay3DPass);
  label->setAnchor(bondCenter);
  node.addDrawable(label);

  Rendering::TextProperties tprop;
  tprop.setAlign(Rendering::TextProperties::HCenter,
                 Rendering::TextProperties::VCenter);
  tprop.setFontFamily(Rendering::TextProperties::SansSerif);
  tprop.setColorRgb(255, 200, 64);
  label->setTextProperties(tprop);
}

void BondCentricTool::drawAtomBondAngles(Rendering::GeometryNode& node,
                                         const RWAtom& atom,
                                         const RWBond& anchorBond)
{
  const Array<RWBond> bonds = m_molecule->bonds(atom);
  auto bondIter(bonds.begin());
  auto bondEnd(bonds.end());
  size_t count = 0;
  while (bondIter != bondEnd) {
    if (*bondIter != anchorBond)
      drawAtomBondAngle(node, atom, anchorBond, *bondIter, getColor(count++));
    ++bondIter;
  }
}

void BondCentricTool::drawAtomBondAngle(Rendering::GeometryNode& node,
                                        const QtGui::RWAtom& atom,
                                        const QtGui::RWBond& anchorBond,
                                        const QtGui::RWBond& otherBond,
                                        const Vector3ub& color)
{
  const RWAtom otherAtom = otherBond.getOtherAtom(atom);
  const RWAtom otherAnchorAtom = anchorBond.getOtherAtom(atom);

  const Vector3f atomPos(atom.position3d().cast<float>());
  const Vector3f otherAtomPos(otherAtom.position3d().cast<float>());
  const Vector3f otherAnchorAtomPos(otherAnchorAtom.position3d().cast<float>());

  const Vector3f otherVector(otherAtomPos - atomPos);
  const Vector3f anchorVector(otherAnchorAtomPos - atomPos);
  const Vector3f anchorUnitVector(anchorVector.normalized());

  const float radius(otherVector.norm() * 0.75f);
  const Vector3f& origin(atomPos);
  const Vector3f start(anchorUnitVector * radius);
  const Vector3f axis(anchorVector.cross(otherVector).normalized());
  const float angle = vectorAngleDegrees(otherVector, anchorVector);
  const Vector3f& labelPos(otherAtomPos);

  auto* sect = new ArcSector;
  node.addDrawable(sect);
  sect->setColor(color);
  sect->setOpacity(127);
  sect->setRenderPass(Rendering::TranslucentPass);
  sect->setArcSector(origin, start, axis, angle, 5.f);

  auto* arc = new ArcStrip;
  node.addDrawable(arc);
  arc->setColor(color);
  arc->setRenderPass(Rendering::OpaquePass);
  arc->setArc(origin, start, axis, angle, 5.f, 1.f);

  auto* label = new Rendering::TextLabel3D;
  label->setText(tr("%L1°").arg(angle, 6, 'f', 1).toStdString());
  label->setRenderPass(Rendering::Overlay3DPass);
  label->setAnchor(labelPos);
  node.addDrawable(label);

  Rendering::TextProperties tprop;
  tprop.setAlign(Rendering::TextProperties::HCenter,
                 Rendering::TextProperties::VCenter);
  tprop.setFontFamily(Rendering::TextProperties::SansSerif);
  tprop.setColorRgb(color);
  label->setTextProperties(tprop);
}

inline bool BondCentricTool::bondContainsAtom(const QtGui::RWBond& bond,
                                              const QtGui::RWAtom& atom) const
{
  return atom == bond.atom1() || atom == bond.atom2();
}

inline void BondCentricTool::transformFragment() const
{
  // Convert the internal float matrix to use the same precision as the atomic
  // coordinates.
  Eigen::Transform<Real, 3, Eigen::Affine> transform(m_transform.cast<Real>());
  for (int it : m_fragment) {
    RWAtom atom = m_molecule->atomByUniqueId(it);
    if (atom.isValid()) {
      Vector3 pos = atom.position3d();
      pos = transform * pos;
      atom.setPosition3d(pos);
    }
  }
}

void BondCentricTool::updatePlaneSnapAngles()
{
  m_planeSnapRef = m_bondVector.unitOrthogonal();
  m_planeSnapAngles.clear();

  // Add bond angles if requested:
  RWBond selectedBond = m_selectedBond.bond();
  if (m_snapPlaneToBonds && selectedBond.isValid()) {
    const RWAtom atom1 = selectedBond.atom1();
    const RWAtom atom2 = selectedBond.atom2();
    for (int i = 0; i < 2; ++i) {
      const RWAtom& atom = i == 0 ? atom1 : atom2;
      const Vector3f atomPos(atom.position3d().cast<float>());
      const Array<RWBond> bonds = m_molecule->bonds(atom);
      for (auto bond : bonds) {
        if (bond != selectedBond) {
          const RWAtom otherAtom(bond.getOtherAtom(atom));
          const Vector3f otherAtomPos(otherAtom.position3d().cast<float>());
          const Vector3f otherBondVector(otherAtomPos - atomPos);
          // Project otherBondVector into the plane normal to m_bondVector
          // (e.g. the rejection of otherBondVector onto m_bondVector)
          const Vector3f rej(
            otherBondVector -
            (otherBondVector.dot(m_bondVector) * m_bondVector));
          float angle(vectorAngleDegrees(m_planeSnapRef, rej, m_bondVector));
          m_planeSnapAngles.insert(angle);
          angle += 180.f;
          if (angle > 180.f)
            angle -= 360.f;
          m_planeSnapAngles.insert(angle);
        }
      }
    }
  }

  // Add default increments only if they are more than 5 degrees away
  // from a bond angle.
  const float minDist(5.f);
  for (float angle = -180.f; angle < 180.f; angle += m_planeSnapIncr) {
    auto upper(m_planeSnapAngles.lower_bound(angle));
    if (upper != m_planeSnapAngles.end()) {
      if (*upper - minDist < angle)
        continue;
      if (upper != m_planeSnapAngles.begin()) {
        auto lower(upper);
        std::advance(lower, -1);
        if (*lower + minDist > angle)
          continue;
      }
      m_planeSnapAngles.insert(angle);
    }
  }
}

// There may be some weirdness around +/-180 since we don't check for
// wrapping, but it should be fine for this use case.
void BondCentricTool::updateSnappedPlaneNormal()
{
  const Vector3f mousePlaneVector(m_planeNormalMouse.cross(m_bondVector));
  const float angle(
    vectorAngleDegrees(m_planeSnapRef, mousePlaneVector, m_bondVector));
  float snappedAngle(angle);
  auto upper(m_planeSnapAngles.lower_bound(angle));
  if (upper != m_planeSnapAngles.end()) {
    if (upper != m_planeSnapAngles.begin()) {
      auto lower(upper);
      std::advance(lower, -1);
      float upperDist = std::fabs(angle - *upper);
      float lowerDist = std::fabs(angle - *lower);
      snappedAngle = upperDist < lowerDist ? *upper : *lower;
    } else {
      snappedAngle = *upper;
    }
  }

  if (angle == snappedAngle) {
    // If the angle didn't change, keep on keepin' on:
    m_planeNormal = m_planeNormalMouse;
  } else {
    // Otherwise, update the vector.
    const Vector3f planeVector =
      Eigen::AngleAxisf(snappedAngle * DEG_TO_RAD_F, m_bondVector) *
      m_planeSnapRef;
    m_planeNormal = planeVector.cross(m_bondVector);
  }
}

inline bool BondCentricTool::fragmentHasAtom(int uid) const
{
  return std::find(m_fragment.begin(), m_fragment.end(), uid) !=
         m_fragment.end();
}

void BondCentricTool::buildFragment(const QtGui::RWBond& bond,
                                    const QtGui::RWAtom& startAtom)
{
  m_fragment.clear();
  if (!buildFragmentRecurse(bond, startAtom, startAtom)) {
    // If this returns false, then a cycle has been found. Only move startAtom
    // in this case.
    m_fragment.clear();
  }
  m_fragment.push_back(m_molecule->atomUniqueId(startAtom));
}

bool BondCentricTool::buildFragmentRecurse(const QtGui::RWBond& bond,
                                           const QtGui::RWAtom& startAtom,
                                           const QtGui::RWAtom& currentAtom)
{
  // does our cycle include both bonded atoms?
  const RWAtom bondedAtom(bond.getOtherAtom(startAtom));

  Array<RWBond> bonds = m_molecule->bonds(currentAtom);

  for (auto& it : bonds) {
    if (it != bond) { // Skip the current bond
      const RWAtom nextAtom = it.getOtherAtom(currentAtom);
      if (nextAtom != startAtom && nextAtom != bondedAtom) {
        // Skip atoms that have already been added. This prevents infinite
        // recursion on cycles in the fragments
        int uid = m_molecule->atomUniqueId(nextAtom);
        if (!fragmentHasAtom(uid)) {
          m_fragment.push_back(uid);
          if (!buildFragmentRecurse(it, startAtom, nextAtom))
            return false;
        }
      } else if (nextAtom == bondedAtom) {
        // If we've found the bonded atom, the bond is in a cycle
        return false;
      }
    } // *it != bond
  }   // foreach bond
  return true;
}

} // namespace Avogadro::QtPlugins
