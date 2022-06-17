/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CUSTOMELEMENTS_H
#define AVOGADRO_QTPLUGINS_CUSTOMELEMENTS_H

#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Manipulate custom element types in the current molecule.
 */
class CustomElements : public QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit CustomElements(QObject* parent_ = nullptr);
  ~CustomElements() override;

  QString name() const override { return tr("Custom Elements"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

private slots:
  void moleculeChanged(unsigned int changes);
  void reassign();

private:
  QtGui::Molecule* m_molecule;
  QAction* m_reassignAction;

  void updateReassignAction();
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CUSTOMELEMENTS_H
