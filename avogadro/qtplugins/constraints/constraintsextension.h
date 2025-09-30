/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CONSTRAINTS_H
#define AVOGADRO_QTPLUGINS_CONSTRAINTS_H

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/extensionplugin.h>
#include <QtCore/QMap>

class QAction;

namespace Avogadro {
namespace QtPlugins {
class ConstraintsDialog;

class ConstraintsExtension : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit ConstraintsExtension(QObject* parent = 0);
  ~ConstraintsExtension() override;

  QString name() const override { return tr("Constraints"); }

  QString description() const override
  {
    return tr("Set constraints for geometry optimizations");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

private slots:
  void openDialog();

private:
  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule = nullptr;
  ConstraintsDialog* m_dialog = nullptr;
};
} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CONSTRAINTS_H
