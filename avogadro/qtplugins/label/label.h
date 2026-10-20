/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_LABEL_H
#define AVOGADRO_QTPLUGINS_LABEL_H

#include <avogadro/core/vector.h>
#include <avogadro/qtgui/sceneplugin.h>

#include <QtCore/QPointer>

#include <string>
namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Render labels to each atom.
 */
class Label : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit Label(QObject* parent = nullptr);
  ~Label() override;

  QString name() const override { return tr("Labels"); }

  QString description() const override
  {
    return tr("Display labels on ball and stick style.");
  }

  QWidget* setupWidget() override;
  bool hasSetupWidget() const override { return true; }

  void process(const QtGui::Molecule& molecule,
               Rendering::GroupNode& node) override;

  DefaultBehavior defaultBehavior() const override
  {
    return DefaultBehavior::False;
  }
public slots:
  void atomLabelType(int index);
  void bondLabelType(int index);
  void residueLabelType(int index);
  void setRadiusScalar(double radius);
  void setLabelScale(double scale);
  void setColor(const QColor& color);

private slots:
  /**
   * Compute partial charges for the pending molecule, from the top-level
   * event loop rather than while the scene is being built, then request a
   * scene rebuild so the labels show them.
   */
  void calculatePartialCharges();

private:
  void processAtom(const QtGui::Molecule& molecule, Rendering::GroupNode& node,
                   size_t layer);
  void requestPartialCharges(const QtGui::Molecule& molecule);
  void processBond(const Core::Molecule& molecule, Rendering::GroupNode& node,
                   size_t layer);
  void processResidue(const Core::Molecule& molecule,
                      Rendering::GroupNode& node, size_t layer);

  Rendering::GroupNode* m_group;
  std::string m_name = "Labels";
  Vector3ub m_color;

  // At most one deferred charge calculation is queued at a time.
  QPointer<QtGui::Molecule> m_chargeMolecule;
  bool m_chargePending = false;
  // The molecule and size of the last FAILED calculation attempt, so a model
  // that fails or returns nothing is not retried on every scene rebuild.
  // Cleared on success: edits clear the stored charges, and they must be
  // recalculated even when the atom count returns to an earlier value.
  QPointer<QtGui::Molecule> m_lastChargeMolecule;
  Index m_lastChargeAtomCount = 0;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_LABEL_H
