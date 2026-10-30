/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CONSTRAINTS_H
#define AVOGADRO_QTPLUGINS_CONSTRAINTS_H

#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/constraint.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/extensionplugin.h>
#include <QtCore/QMap>
#include <QtCore/QVector>

class QAction;

namespace Avogadro {
namespace QtGui {
class CommandArguments;
}
namespace QtPlugins {
class ConstraintsDialog;

class ConstraintsExtension : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit ConstraintsExtension(QObject* parent = nullptr);
  ~ConstraintsExtension() override;

  QString name() const override { return tr("Constraints"); }

  QString description() const override
  {
    return tr("Set constraints for geometry optimizations");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

  /// listConstraints/addConstraint/removeConstraint/clearConstraints, the
  /// scripting/RPC equivalents of the dialog, are described by the command
  /// registry (see registerConstraintCommands()).
  bool handleCommand(const QString& command,
                     const QVariantMap& options) override;

private slots:
  void openDialog();

private:
  /// Add the four constraint commands to the command registry.
  void registerConstraintCommands();

  /// Run addConstraint: add a constraint, or update one on the same atoms.
  void addConstraint(const QtGui::CommandArguments& args);
  /// Run removeConstraint: remove the constraint on the given atoms.
  void removeConstraint(const QtGui::CommandArguments& args);

  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule = nullptr;
  ConstraintsDialog* m_dialog = nullptr;
};
} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CONSTRAINTS_H
