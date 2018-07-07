/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  Adapted from Avogadro 1.x with the following authors' permission:
  Copyright (C) 2007 by Shahzad Ali
  Copyright (C) 2007 by Ross Braithwaite
  Copyright (C) 2007 by James Bunt
  Copyright (C) 2007,2008 by Marcus D. Hanwell
  Copyright (C) 2006,2007 by Benoit Jacob

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_BONDCENTRICTOOL_H
#define AVOGADRO_QTPLUGINS_BONDCENTRICTOOL_H

#include <avogadro/qtgui/toolplugin.h>

#include <avogadro/rendering/primitive.h>

#include <avogadro/qtgui/persistentatom.h>
#include <avogadro/qtgui/persistentbond.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <avogadro/core/avogadrocore.h>

#include <QtCore/QPoint>

#include <Eigen/Geometry>

#include <set>

namespace Avogadro {
namespace Rendering {
class GeometryNode;
}

namespace QtPlugins {

/**
 * @brief BondCentricTool manipulates molecular geometry by adjusting bond
 * angles/lengths.
 *
 * @note This class is adapted from the class of the same name in Avogadro 1.x,
 * written by Shahzad Ali, Ross Braithwaite, James Bunt, Marcus D. Hanwell, and
 * Benoit Jacob.
 */
class BondCentricTool : public QtGui::ToolPlugin
{
  Q_OBJECT
public:
  explicit BondCentricTool(QObject* parent_ = nullptr);
  ~BondCentricTool() override;

  QString name() const override;
  QString description() const override;
  unsigned char priority() const override { return 40; }
  QAction* activateAction() const override { return m_activateAction; }
  QWidget* toolWidget() const override;

  void setMolecule(QtGui::Molecule*) override;
  void setEditMolecule(QtGui::RWMolecule*) override;
  void setGLWidget(QtOpenGL::GLWidget* widget) override;
  void setGLRenderer(Rendering::GLRenderer* ren) override;

  QUndoCommand* mousePressEvent(QMouseEvent* e) override;
  QUndoCommand* mouseDoubleClickEvent(QMouseEvent* e) override;
  QUndoCommand* mouseMoveEvent(QMouseEvent* e) override;
  QUndoCommand* mouseReleaseEvent(QMouseEvent* e) override;

  void draw(Rendering::GroupNode& node) override;

private:
  enum MoveState
  {
    IgnoreMove = 0,
    RotatePlane,
    RotateBondedAtom,
    AdjustBondLength,
    RotateNeighborAtom
  };

  enum ResetBondBehavior
  {
    KeepBond = 0,
    ResetBond
  };
  void reset(ResetBondBehavior bond = ResetBond);

  void initializeBondVectors();
  void updateBondVector();

  // Mouse press event handlers:
  QUndoCommand* initRotatePlane(QMouseEvent* e,
                                const Rendering::Identifier& ident);
  QUndoCommand* initRotateBondedAtom(QMouseEvent* e,
                                     const QtGui::RWAtom& clickedAtom);
  QUndoCommand* initAdjustBondLength(QMouseEvent* e,
                                     const QtGui::RWAtom& clickedAtom);
  QUndoCommand* initRotateNeighborAtom(QMouseEvent* e,
                                       const QtGui::RWAtom& clickedAtom,
                                       const QtGui::RWAtom& anchorAtom);

  // Mouse move event handlers:
  QUndoCommand* rotatePlane(QMouseEvent* e);
  QUndoCommand* rotateBondedAtom(QMouseEvent* e);
  QUndoCommand* adjustBondLength(QMouseEvent* e);
  QUndoCommand* rotateNeighborAtom(QMouseEvent* e);

  // Drawing helpers:
  void drawBondQuad(Rendering::GeometryNode& node,
                    const QtGui::RWBond& bond) const;
  void drawBondAngle(Rendering::GeometryNode& node,
                     const QtGui::RWBond& selectedBond,
                     const QtGui::RWBond& movingBond) const;
  void drawBondLengthLabel(Rendering::GeometryNode& node,
                           const QtGui::RWBond& bond);
  void drawAtomBondAngles(Rendering::GeometryNode& node,
                          const QtGui::RWAtom& atom,
                          const QtGui::RWBond& anchorBond);
  void drawAtomBondAngle(Rendering::GeometryNode& node,
                         const QtGui::RWAtom& atom,
                         const QtGui::RWBond& anchorBond,
                         const QtGui::RWBond& otherBond,
                         const Vector3ub& color);

  // Bond utilities
  bool bondContainsAtom(const QtGui::RWBond& bond,
                        const QtGui::RWAtom& atom) const;
  QtGui::RWAtom otherBondedAtom(const QtGui::RWBond& bond,
                                const QtGui::RWAtom& atom) const;

  // The 'fragment' is the SkeletonTree of the 1.x implementation. It is a list
  // of atoms created by buildFragment(bond, startAtom), which walks the bonds
  // connected to startAtom (not including the passed-in bond), adding each
  // atom it encounters to the list, and then walking that atom's bonds. If a
  // cycle is detected, only startAtom is added to m_fragment.
  void resetFragment() { m_fragment.clear(); }
  bool fragmentHasAtom(int uid) const;
  void buildFragment(const QtGui::RWBond& bond, const QtGui::RWAtom& startAtom);
  bool buildFragmentRecurse(const QtGui::RWBond& bond,
                            const QtGui::RWAtom& startAtom,
                            const QtGui::RWAtom& currentAtom);
  // Use transformFragment to transform the position of each atom in the
  // fragment by m_transform.
  void transformFragment() const;

  QAction* m_activateAction;
  QtGui::RWMolecule* m_molecule;
  Rendering::GLRenderer* m_renderer;
  MoveState m_moveState;
  QPoint m_clickedPoint;
  QPoint m_lastDragPoint;
  Vector3f m_bondVector;
  Vector3f m_planeNormalMouse;
  Vector3f m_planeNormal;

  // unique ids of atoms that will need to be moved:
  std::vector<int> m_fragment;
  Eigen::Affine3f m_transform;

  // Snap angles for RotatePlane. Angles are relative to m_planeSnapRef and
  // follow a right-hand rule around m_bondVector. Range is [-180, 180).
  std::set<float> m_planeSnapAngles;
  float m_planeSnapIncr;
  Vector3f m_planeSnapRef;
  bool m_snapPlaneToBonds;
  void updatePlaneSnapAngles();
  void updateSnappedPlaneNormal();

  QtGui::RWMolecule::PersistentBondType m_selectedBond;
  QtGui::RWMolecule::PersistentAtomType m_anchorAtom;
  QtGui::RWMolecule::PersistentAtomType m_clickedAtom;
};

inline QString BondCentricTool::name() const
{
  return tr("Bond centric manipulation tool.");
}

inline QString BondCentricTool::description() const
{
  return tr("Tool used to edit molecular geometry by changing bond lengths and "
            "angles.");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_BONDCENTRICTOOL_H
