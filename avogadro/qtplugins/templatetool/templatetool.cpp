/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "templatetool.h"
#include "templatetoolwidget.h"

#include <avogadro/core/atom.h>
#include <avogadro/core/bond.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/io/cjsonformat.h>
#include <avogadro/io/fileformatmanager.h>

#include <avogadro/qtgui/hydrogentools.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/glrenderer.h>

#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/textlabel2d.h>
#include <avogadro/rendering/textlabel3d.h>
#include <avogadro/rendering/textproperties.h>

#include <QAction>
#include <QtGui/QClipboard>
#include <QtGui/QIcon>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QWheelEvent>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QWidget>

#include <QtCore/QDebug>
#include <QtCore/QFile>
#include <QtCore/QMimeData>
#include <QtCore/QTimer>

#include <limits>

namespace {
const unsigned char INVALID_ATOMIC_NUMBER =
  std::numeric_limits<unsigned char>::max();
}

namespace Avogadro {
namespace QtPlugins {

using QtGui::Molecule;
using QtGui::RWAtom;
using QtGui::RWBond;
using QtGui::RWMolecule;
using QtOpenGL::GLWidget;

using Avogadro::Core::Elements;
using Avogadro::Io::CjsonFormat;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::GroupNode;
using Avogadro::Rendering::Identifier;
using Avogadro::Rendering::TextLabel2D;
using Avogadro::Rendering::TextLabel3D;
using Avogadro::Rendering::TextProperties;

TemplateTool::TemplateTool(QObject* parent_)
  : QtGui::ToolPlugin(parent_), m_activateAction(new QAction(this)),
    m_molecule(NULL), m_glWidget(NULL), m_renderer(NULL),
    m_toolWidget(new TemplateToolWidget(qobject_cast<QWidget*>(parent_))),
    m_pressedButtons(Qt::NoButton),
    m_clickedAtomicNumber(INVALID_ATOMIC_NUMBER), m_bondAdded(false),
    m_fixValenceLater(false)
{
  QString shortcut = tr("Ctrl+3", "control-key 3");
  m_activateAction->setText(tr("Template"));
  m_activateAction->setToolTip(
    tr("Template Tool\t(%1)\n\n"
       "Insert fragments, including metal centers.\n"
       "Select an element and coordination geometry, "
       "then click to insert a fragment.\n\n"
       "Select a ligand or functional group and click "
       "on a hydrogen atom to attach it.")
      .arg(shortcut));
  setIcon();
  reset();
}

TemplateTool::~TemplateTool() {}

void TemplateTool::setIcon(bool darkTheme)
{
  if (darkTheme)
    m_activateAction->setIcon(QIcon(":/icons/template_dark.svg"));
  else
    m_activateAction->setIcon(QIcon(":/icons/template_light.svg"));
}

QWidget* TemplateTool::toolWidget() const
{
  return m_toolWidget;
}

QUndoCommand* TemplateTool::mousePressEvent(QMouseEvent* e)
{
  clearKeyPressBuffer();
  if (!m_renderer)
    return NULL;

  updatePressedButtons(e, false);
  m_clickPosition = e->pos();

  if (m_molecule) {
    m_molecule->setInteractive(true);
  }

  if (m_pressedButtons & Qt::LeftButton) {
    m_clickedObject = m_renderer->hit(e->pos().x(), e->pos().y());

    switch (m_clickedObject.type) {
      case Rendering::InvalidType:
        emptyLeftClick(e);
        return NULL;
      case Rendering::AtomType:
        atomLeftClick(e);
        return NULL;
      default:
        break;
    }
  } else if (m_pressedButtons & Qt::RightButton) {
    m_clickedObject = m_renderer->hit(e->pos().x(), e->pos().y());

    switch (m_clickedObject.type) {
      case Rendering::AtomType:
        atomRightClick(e);
        return NULL;
      default:
        break;
    }
  }

  return NULL;
}

QUndoCommand* TemplateTool::mouseReleaseEvent(QMouseEvent* e)
{
  if (!m_renderer)
    return NULL;

  updatePressedButtons(e, true);

  if (m_molecule) {
    m_molecule->setInteractive(false);
  }

  if (m_clickedObject.type == Rendering::InvalidType)
    return NULL;

  switch (e->button()) {
    case Qt::LeftButton:
    case Qt::RightButton:
      reset();
      e->accept();
      break;
    default:
      break;
  }

  return NULL;
}

QUndoCommand* TemplateTool::mouseMoveEvent(QMouseEvent* e)
{
  if (!m_renderer)
    return NULL;

  if (m_pressedButtons & Qt::LeftButton)
    if (m_clickedObject.type == Rendering::AtomType)
      atomLeftDrag(e);

  return NULL;
}

QUndoCommand* TemplateTool::keyPressEvent(QKeyEvent* e)
{
  if (e->text().isEmpty())
    return NULL;

  e->accept();

  // check which tab is currently active
  int currentTab = m_toolWidget->currentTab();

  // if it's arrow keys, change tabs
  if (e->key() == Qt::Key_Left || e->key() == Qt::Key_Right ||
      e->key() == Qt::Key_BracketLeft || e->key() == Qt::Key_BracketRight) {
    // cycle through tabs
    // the widget will handle any wrap-around
    if (e->key() == Qt::Key_Left || e->key() == Qt::Key_BracketLeft) {
      currentTab--;
    } else {
      currentTab++;
    }
    m_toolWidget->setCurrentTab(currentTab);
    return NULL;
  }

  // Set a timer to clear the buffer on first keypress:
  if (m_keyPressBuffer.isEmpty())
    QTimer::singleShot(2000, this, SLOT(clearKeyPressBuffer()));

  m_keyPressBuffer.append(m_keyPressBuffer.isEmpty() ? e->text().toUpper()
                                                     : e->text().toLower());

  if (m_keyPressBuffer.size() >= 3) {
    clearKeyPressBuffer();
    return NULL;
  }

  if (currentTab == 0) {
    // if it's + or -, change the formal charge
    if (e->key() == Qt::Key_Plus || e->key() == Qt::Key_Minus) {
      int formalCharge = m_toolWidget->formalCharge();
      if (e->key() == Qt::Key_Plus)
        formalCharge++;
      else
        formalCharge--;
      m_toolWidget->setFormalCharge(formalCharge);
      clearKeyPressBuffer();
      return NULL;
    }

    // metal center -- interpret as an element
    int atomicNum =
      Core::Elements::atomicNumberFromSymbol(m_keyPressBuffer.toStdString());

    if (atomicNum != Avogadro::InvalidElement)
      m_toolWidget->setAtomicNumber(static_cast<unsigned char>(atomicNum));
    else {
      // if it's a number, try a coordination number
      bool ok = false;
      int coordinationNumber = m_keyPressBuffer.toInt(&ok);
      if (ok) {
        unsigned char geometry = 0;
        switch (coordinationNumber) {
          // 1, 2, 3, 4, 4, 5, 5, 6, 6, 7, 8 are valid
          case 1:
            break;
          case 2:
            geometry = 1;
            break;
          case 3:
            geometry = 2;
            break;
          case 4:
            geometry = 3;
            break;
          case 44:
            geometry = 4;
            break;
          case 5:
            geometry = 5;
            break;
          case 55:
            geometry = 6;
            break;
          case 6:
            geometry = 7;
            break;
          case 66:
            geometry = 8;
            break;
          case 7:
            geometry = 9;
            break;
          case 8:
            geometry = 10;
            break;
          default:
            // do nothing, invalid coordination number
            clearKeyPressBuffer();
            break;
        }
        m_toolWidget->setCoordination(geometry);
      }
    }
  } else if (currentTab == 1) {
    // ligand
    // e.g. bpy = bipyridine
    // e.g. edta, tpy, etc.
  } else if (currentTab == 2) {
    // functional group
    // e.g. c8 = octyl group
    // p = phenyl group
  }

  return NULL;
}

void TemplateTool::draw(Rendering::GroupNode&) {}

void TemplateTool::updatePressedButtons(QMouseEvent* e, bool release)
{
  /// @todo Use modifier keys on mac
  if (release)
    m_pressedButtons &= e->buttons();
  else
    m_pressedButtons |= e->buttons();
}

void TemplateTool::reset()
{
  if (m_fixValenceLater) {
    Index a1 = m_newObject.index;
    Index a2 = m_bondedAtom.index;
    Index a3 = m_clickedObject.index;

    // order them
    if (a1 > a2)
      std::swap(a1, a2);
    if (a1 > a3)
      std::swap(a1, a3);
    if (a2 > a3)
      std::swap(a2, a3);

    // This preserves the order so they are adjusted in order.
    Core::Array<Index> atomIds;
    atomIds.push_back(a3);
    atomIds.push_back(a2);
    atomIds.push_back(a1);
    // This function checks to make sure the ids are valid, so no need
    // to check out here.
    m_molecule->adjustHydrogens(atomIds);

    Molecule::MoleculeChanges changes = Molecule::Atoms | Molecule::Added;
    changes |= Molecule::Bonds | Molecule::Added | Molecule::Removed;

    m_molecule->emitChanged(changes);

    m_fixValenceLater = false;
  }

  m_clickedObject = Identifier();
  m_newObject = Identifier();
  m_bondedAtom = Identifier();
  m_clickPosition = QPoint();
  m_pressedButtons = Qt::NoButton;
  m_clickedAtomicNumber = INVALID_ATOMIC_NUMBER;
  m_bondAdded = false;

  emit drawablesChanged();
}

void TemplateTool::emptyLeftClick(QMouseEvent* e)
{
  // Get the coordinates of the clicked position
  if (m_renderer == nullptr)
    return;

  m_toolWidget->selectedUIDs().clear();
  Vector2f windowPos(e->localPos().x(), e->localPos().y());
  Vector3f atomPos = m_renderer->camera().unProject(windowPos);
  // center of inserted template
  Vector3 center(0.0f, 0.0f, 0.0f);

  CjsonFormat ff;
  Molecule templateMolecule;

  // before we do anything, check if it's a metal or a ligand
  // in the dialog
  int currentTab = m_toolWidget->currentTab();
  if (currentTab == 0) { // metal center
    QFile templ(":/templates/centers/" + m_toolWidget->coordinationString() +
                ".cjson");
    if (!templ.open(QFile::ReadOnly | QFile::Text))
      return;
    QTextStream templateStream(&templ);

    if (!ff.readString(templateStream.readAll().toStdString(),
                       templateMolecule))
      return;

    // Add the atom and hydrogens around it following template
    [[maybe_unused]] size_t centerIndex = 0;
    for (size_t i = 0; i < templateMolecule.atomCount(); i++) {
      if (templateMolecule.atomicNumber(i) != 1) {
        center = templateMolecule.atomPosition3d(i);
        centerIndex = i;
        templateMolecule.setAtomicNumber(i, m_toolWidget->atomicNumber());
        templateMolecule.setFormalCharge(i, m_toolWidget->formalCharge());
        continue;
      }
    }
    // done with metal center and coordination
  } else {
    // ligand
    // check if it's clipboard first
    if (m_toolWidget->ligandString() == tr("Clipboard")) {
      const QMimeData* mimeData(QApplication::clipboard()->mimeData());

      if (!mimeData) {
        return;
      }

      // Try to find a reader that can handle the available mime-types.
      Io::FileFormatManager& mgr = Io::FileFormatManager::instance();
      QStringList mimeTypes(mimeData->formats());
      Io::FileFormat* pastedFormat = nullptr;
      QByteArray pastedData;
      Io::FileFormat::Operations ops(Io::FileFormat::Read |
                                     Io::FileFormat::String);
      foreach (const QString& mimeType, mimeTypes) {
        if ((pastedFormat =
               mgr.newFormatFromMimeType(mimeType.toStdString(), ops))) {
          pastedData = mimeData->data(mimeType);
          break;
        }
      }

      // No mime-type match, default to cjson.
      if (!pastedFormat && mimeData->hasText()) {
        pastedFormat = new Io::CjsonFormat;
        pastedData = mimeData->text().toLatin1();
      }

      if (pastedFormat == nullptr)
        return;

      // we have a format, so try to insert the new bits into the molecule
      bool success = pastedFormat->readString(
        std::string(pastedData.constData(), pastedData.size()),
        templateMolecule);

      if (!success)
        return;

      center = templateMolecule.centerOfGeometry();
      // change the dummy atom(s) to hydrogen
      for (size_t i = 0; i < templateMolecule.atomCount(); i++) {
        if (templateMolecule.atomicNumber(i) == 0) {
          templateMolecule.setAtomicNumber(i, 1);
          templateMolecule.setFormalCharge(i, 0);
        }
      }

      // done with clipboard ligands
    } else { // a ligand file
      QString path;
      if (m_toolWidget->ligandString().endsWith(".cjson")) {
        // we already have the full path .. from the insert browser
        path = m_toolWidget->ligandString();
      } else {
        path = ":/templates/ligands/" + m_toolWidget->ligandString() + ".cjson";
      }

      QFile templ(path);
      if (!templ.open(QFile::ReadOnly | QFile::Text))
        return;
      QTextStream templateStream(&templ);

      if (!ff.readString(templateStream.readAll().toStdString(),
                         templateMolecule))
        return;

      center = templateMolecule.centerOfGeometry();
      // change the dummy atom(s) to hydrogen
      for (size_t i = 0; i < templateMolecule.atomCount(); i++) {
        if (templateMolecule.atomicNumber(i) == 0) {
          templateMolecule.setAtomicNumber(i, 1);
          templateMolecule.setFormalCharge(i, 0);
        }
      }

      // done with ligand
    }
  }

  // move the template to the clicked position
  for (size_t i = 0; i < templateMolecule.atomCount(); i++) {
    Vector3 pos =
      templateMolecule.atomPosition3d(i) - center + atomPos.cast<double>();
    templateMolecule.setAtomPosition3d(i, pos);
  }

  size_t firstIndex = m_molecule->atomCount();
  m_molecule->appendMolecule(templateMolecule, tr("Insert Template"));

  Molecule::MoleculeChanges changes =
    Molecule::Atoms | Molecule::Bonds | Molecule::Added;

  // m_fixValenceLater = true; // add hydrogens
  m_fixValenceLater = false;

  // Update the clicked object
  m_clickedObject.type = Rendering::AtomType;
  m_clickedObject.molecule = m_molecule;
  m_clickedObject.index = firstIndex;

  // Emit changed signal
  m_molecule->emitChanged(changes);

  e->accept();
}

Vector3 rotateLigandCoords(Vector3 in, Vector3 centerVector, Vector3 outVector)
{
  if (centerVector.norm() == 0.0 || outVector.norm() == 0.0)
    return in;
  Vector3 axis = centerVector.cross(outVector);
  if (axis.norm() < 1e-12) { // vectors are parallel, let's pick an arbitrary
                             // perpendicular axis
    Matrix3 rotx =
      Eigen::AngleAxisd(M_PI / 2.0, Vector3(1.0, 0.0, 0.0)).toRotationMatrix();
    Matrix3 roty =
      Eigen::AngleAxisd(M_PI / 2.0, Vector3(0.0, 1.0, 0.0)).toRotationMatrix();
    axis = centerVector.cross(rotx * outVector);
    if (axis.norm() < 1e-12)
      axis = centerVector.cross(roty * outVector);
  }
  axis.normalize();
  double cosine =
    centerVector.dot(outVector) / centerVector.norm() / outVector.norm();
  double angle = (abs(cosine) < 1.0) ? acos(cosine) : 0.0;
  Matrix3 rot = Eigen::AngleAxisd(angle, axis).toRotationMatrix();
  return rot * in;
}

Matrix3 applyKabsch(std::vector<Vector3> templatePoints,
                    std::vector<Vector3> moleculePoints)
{
  assert(templatePoints.size() == moleculePoints.size());
  MatrixX TP(templatePoints.size(), 3);
  MatrixX MP(templatePoints.size(), 3);
  for (size_t i = 0; i < templatePoints.size(); i++) {
    TP.row(i) = templatePoints[i];
    MP.row(i) = moleculePoints[i];
  }
  Matrix3 H = TP.transpose() * MP;
  Eigen::JacobiSVD<MatrixX> svd(H, Eigen::ComputeFullU | Eigen::ComputeFullV);
  MatrixX U = svd.matrixU();
  Matrix3 V = svd.matrixV();
  Matrix3 Idd = Matrix3::Identity();
  Idd(2, 2) = copysign(1.0, (V * U.transpose()).determinant());
  Matrix3 r = V * Idd * U.transpose();
  return r;
}

void TemplateTool::atomLeftClick(QMouseEvent*)
{
  size_t selectedIndex = m_clickedObject.index;
  // if it's a valid selected atom and a hydrogen or dummy atom
  if (m_molecule->atom(selectedIndex).isValid() &&
      (m_molecule->atomicNumber(selectedIndex) == 1 ||
       m_molecule->atomicNumber(selectedIndex) == 0)) {
    m_toolWidget->selectedUIDs().push_back(
      m_molecule->atomUniqueId(selectedIndex));
    if (static_cast<int>(m_toolWidget->selectedUIDs().size()) !=
        m_toolWidget->denticity())
      return;

    // Get the ligand template
    // - check if we should use the clipboard
    // - otherwise use the template
    Molecule templateMolecule;

    if (m_toolWidget->ligandString() == tr("Clipboard")) {
      const QMimeData* mimeData(QApplication::clipboard()->mimeData());

      if (!mimeData) {
        return;
      }

      // Try to find a reader that can handle the available mime-types.
      Io::FileFormatManager& mgr = Io::FileFormatManager::instance();
      QStringList mimeTypes(mimeData->formats());
      Io::FileFormat* pastedFormat = nullptr;
      QByteArray pastedData;
      Io::FileFormat::Operations ops(Io::FileFormat::Read |
                                     Io::FileFormat::String);
      foreach (const QString& mimeType, mimeTypes) {
        if ((pastedFormat =
               mgr.newFormatFromMimeType(mimeType.toStdString(), ops))) {
          pastedData = mimeData->data(mimeType);
          break;
        }
      }

      // No mime-type match, default to cjson.
      if (!pastedFormat && mimeData->hasText()) {
        pastedFormat = new Io::CjsonFormat;
        pastedData = mimeData->text().toLatin1();
      }

      if (pastedFormat == nullptr)
        return;

      // we have a format, so try to insert the new bits into the molecule
      bool success = pastedFormat->readString(
        std::string(pastedData.constData(), pastedData.size()),
        templateMolecule);

      if (!success)
        return;

    } else {
      QString path;
      if (m_toolWidget->ligandString().endsWith(".cjson")) {
        // we already have the full path .. from the insert browser
        path = m_toolWidget->ligandString();
      } else {
        path = ":/templates/ligands/" + m_toolWidget->ligandString() + ".cjson";
      }

      QFile templ(path);
      if (!templ.open(QFile::ReadOnly | QFile::Text))
        return;
      QTextStream templateStream(&templ);

      CjsonFormat ff;

      if (!ff.readString(templateStream.readAll().toStdString(),
                         templateMolecule))
        return;
    }

    // Find dummy atom in template and get all necessary info
    // for haptic ligands, we pick the dummy atom that's
    // furthest from the centroid of the carbon atoms
    Vector3 centroid(0.0, 0.0, 0.0);
    unsigned carbonCount = 0;
    for (size_t i = 0; i < templateMolecule.atomCount(); ++i) {
      if (templateMolecule.atomicNumber(i) == 6) {
        carbonCount++;
        centroid += templateMolecule.atomPosition3d(i);
      }
    }
    if (carbonCount > 1)
      centroid = centroid / carbonCount;

    size_t templateDummyIndex = 0;
    std::vector<size_t> templateLigandIndices;
    std::vector<size_t> templateLigandUIDs;
    float maxDistance = 0.0;
    for (size_t i = 0; i < templateMolecule.atomCount(); ++i) {
      // in some ligands (e.g., haptic) we might have two dummy atoms
      // so we only select the one furthest from the ligand centroid
      if (templateMolecule.atomicNumber(i) == 0) {
        Vector3 delta = templateMolecule.atomPosition3d(i) - centroid;
        if (delta.squaredNorm() < maxDistance)
          continue; // too close to the centroid

        maxDistance = delta.squaredNorm();
        templateDummyIndex = i;
        templateLigandIndices.clear();
        templateLigandUIDs.clear();
        for (const auto& bond : templateMolecule.bonds(i)) {
          size_t newIndex = bond.getOtherAtom(i).index();
          templateLigandIndices.push_back(newIndex);
          templateLigandUIDs.push_back(templateMolecule.atomUniqueId(newIndex));
        }
      }
    }

    // Find center atom in our current molecule and get all necessary info
    // - first check to see if there is a bond
    Vector3 moleculeLigandOutVector(0.0, 0.0, 0.0);
    Vector3 displacement(0.0, 0.0, 0.0);
    [[maybe_unused]] Vector3 centerPosition =
      m_molecule->atomPosition3d(selectedIndex);
    size_t moleculeCenterIndex = selectedIndex;
    size_t moleculeCenterUID = m_molecule->atomUniqueId(moleculeCenterIndex);

    if (m_molecule->bonds(selectedIndex).size() != 0) {
      moleculeCenterIndex =
        m_molecule->bonds(selectedIndex)[0].getOtherAtom(selectedIndex).index();
      moleculeCenterUID = m_molecule->atomUniqueId(moleculeCenterIndex);
      for (size_t UID : m_toolWidget->selectedUIDs()) {
        size_t index = m_molecule->atomByUniqueId(UID).index();
        Vector3 newPos = m_molecule->atomPosition3d(index);
        moleculeLigandOutVector +=
          newPos - m_molecule->atomPosition3d(moleculeCenterIndex);
      }

      // Estimate and try to realize bond distances
      for (size_t i = 0; i < templateLigandIndices.size(); i++) {
        unsigned char ligandAtomicNumber =
          templateMolecule.atomicNumber(templateLigandIndices[i]);
        ligandAtomicNumber = (ligandAtomicNumber == 0) ? 6 : ligandAtomicNumber;
        // Estimate as the sum of covalent radii
        double bondDistance = Elements::radiusCovalent(ligandAtomicNumber) +
                              Elements::radiusCovalent(
                                m_molecule->atomicNumber(moleculeCenterIndex));
        Vector3 inVector =
          templateMolecule.atomPosition3d(templateDummyIndex) -
          templateMolecule.atomPosition3d(templateLigandIndices[i]);
        Vector3 correctionVector = inVector;
        correctionVector.normalize();
        correctionVector *= bondDistance - inVector.norm();
        displacement += correctionVector;
      }
      displacement *= 1.0 / templateLigandIndices.size();
    } else {
      // direction can be random
      displacement = Eigen::Vector3d::Random();
    }
    Vector3 newPos =
      templateMolecule.atomPosition3d(templateDummyIndex) + displacement;
    templateMolecule.setAtomPosition3d(templateDummyIndex, newPos);

    // Translate template so dummy atom is brought to center atom
    for (size_t i = 0; i < templateMolecule.atomCount(); i++) {
      if (i != templateDummyIndex) {
        templateMolecule.setAtomPosition3d(
          i, templateMolecule.atomPosition3d(i) -
               templateMolecule.atomPosition3d(templateDummyIndex) +
               m_molecule->atomPosition3d(moleculeCenterIndex));
      }
    }

    if (m_molecule->bonds(selectedIndex).size() != 0) {
      // Create arrays with the points to align and apply Kabsch algorithm
      std::vector<Vector3> templateLigandPositions;
      for (size_t index : templateLigandIndices)
        templateLigandPositions.push_back(
          templateMolecule.atomPosition3d(index) -
          m_molecule->atomPosition3d(moleculeCenterIndex));
      std::vector<Vector3> moleculeLigandPositions;
      for (size_t UID : m_toolWidget->selectedUIDs())
        moleculeLigandPositions.push_back(
          m_molecule->atomPosition3d(m_molecule->atomByUniqueId(UID).index()) -
          m_molecule->atomPosition3d(moleculeCenterIndex));
      Matrix3 rotation =
        applyKabsch(templateLigandPositions, moleculeLigandPositions);
      for (size_t i = 0; i < templateMolecule.atomCount(); i++) {
        if (i != templateDummyIndex) {
          templateMolecule.setAtomPosition3d(
            i, rotation * (templateMolecule.atomPosition3d(i) -
                           m_molecule->atomPosition3d(moleculeCenterIndex)) +
                 m_molecule->atomPosition3d(moleculeCenterIndex));
        }
      }

      // Rotate partially aligned template to align "out" vectors
      Vector3 templateLigandOutVector(0.0, 0.0, 0.0);
      for (size_t index : templateLigandIndices) {
        Vector3 pos = templateMolecule.atomPosition3d(index);
        templateLigandOutVector +=
          pos - m_molecule->atomPosition3d(moleculeCenterIndex);
      }
      for (size_t i = 0; i < templateMolecule.atomCount(); i++) {
        if (templateMolecule.atomicNumber(i) != 0) {
          templateMolecule.setAtomPosition3d(
            i, rotateLigandCoords(
                 templateMolecule.atomPosition3d(i) -
                   m_molecule->atomPosition3d(moleculeCenterIndex),
                 templateLigandOutVector, moleculeLigandOutVector) +
                 m_molecule->atomPosition3d(moleculeCenterIndex));
        }
      }
    }

    // Remove dummy atoms
    for (size_t i = 0; i < templateMolecule.atomCount(); i++) {
      if (templateMolecule.atomicNumber(i) == 0) {
        templateMolecule.removeAtom(i);
        i--; // repeat index to counteract swapping
      }
    }

    std::vector<size_t> templateNewLigandIndices;
    for (size_t UID : templateLigandUIDs) {
      auto atom = templateMolecule.atomByUniqueId(UID);
      if (atom.isValid())
        templateNewLigandIndices.push_back(atom.index());
    }

    // Remove selected atoms and insert ligand
    // (unless there wasn't a bond to begin with)
    if (m_molecule->bonds(selectedIndex).size() != 0) {
      for (size_t UID : m_toolWidget->selectedUIDs())
        m_molecule->removeAtom(m_molecule->atomByUniqueId(UID).index());
    }
    size_t moleculeBaseIndex = m_molecule->atomCount();
    m_molecule->appendMolecule(templateMolecule, tr("Insert Ligand"));

    // Create new bonds
    size_t moleculeCenterNewIndex =
      m_molecule->atomByUniqueId(moleculeCenterUID).index();
    for (size_t index : templateNewLigandIndices)
      m_molecule->addBond(index + moleculeBaseIndex, moleculeCenterNewIndex);

    m_toolWidget->selectedUIDs().clear();
  }
}

void TemplateTool::atomRightClick(QMouseEvent* e)
{
  e->accept();
  m_molecule->removeAtom(m_clickedObject.index);
  m_molecule->emitChanged(Molecule::Atoms | Molecule::Removed);
}

void TemplateTool::atomLeftDrag(QMouseEvent*)
{
  // by default, don't allow drags for bonds
  return;
}

} // namespace QtPlugins
} // namespace Avogadro
