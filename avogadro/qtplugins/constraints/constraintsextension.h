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

  /// Registers listConstraints/addConstraint/removeConstraint/
  /// clearConstraints, the scripting/RPC equivalents of the dialog.
  void registerCommands() override;
  bool handleCommand(const QString& command,
                     const QVariantMap& options) override;

private slots:
  void openDialog();

private:
  /**
   * Parse the "atoms" option shared by the add/removeConstraint commands: a
   * JSON array of 2 (distance), 3 (angle) or 4 (torsion) zero-based atom
   * indices. On success, fills @p indices (in the given order) and returns
   * true; otherwise fills @p error with a message identifying what was
   * wrong and returns false.
   */
  bool parseAtomIndices(const QVariantMap& options, QVector<Index>& indices,
                        QString& error) const;

  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule = nullptr;
  ConstraintsDialog* m_dialog = nullptr;
};
} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CONSTRAINTS_H
