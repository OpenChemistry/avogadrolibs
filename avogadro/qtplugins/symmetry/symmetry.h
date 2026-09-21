/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SYMMETRY_H
#define AVOGADRO_QTPLUGINS_SYMMETRY_H

#include <avogadro/qtgui/extensionplugin.h>

#include "symmetrywidget.h"

namespace msym {
extern "C"
{
#include <libmsym/msym.h>
}
} // namespace msym

namespace Avogadro {
namespace QtPlugins {
class SymmetryWidget;

/**
 * @brief symmetry functionality.
 */
class Symmetry : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit Symmetry(QObject* parent_ = nullptr);
  ~Symmetry() override;

  QString name() const override { return tr("Symmetry"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

  void registerCommands() override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

  bool handleCommand(const QString& command,
                     const QVariantMap& options) override;

  void moleculeChanged(unsigned int changes);

private slots:
  void updateActions();

  void viewSymmetry();

  void detectSymmetry();

  void symmetrizeMolecule();

private:
  /// Runs libmsym over the current molecule and, when a panel exists,
  /// fills it in. This is the body of detectSymmetry(), reachable without a
  /// panel so that a command can use it.
  /// @param thresholds The tolerance preset, or nullptr for the panel's
  /// current setting (tight when there is no panel).
  /// @param pointGroup When non-null, set to the plain-text symbol.
  /// @param error When non-null, set to the reason for a false return.
  bool runSymmetryDetection(msym::msym_thresholds_t* thresholds,
                            QString* pointGroup, QString* error);

  /// Snaps the atoms onto the point group in the current libmsym context,
  /// re-detecting first when the geometry has changed since detection.
  /// @param symmetryError When non-null, set to the deviation libmsym had
  /// to remove, in Angstrom.
  /// @param error When non-null, set to the reason for a false return.
  bool runSymmetrize(double* symmetryError, QString* error);

  /// Blanks the panel's four result views, when there is a panel. Every
  /// libmsym failure path goes through here.
  void clearSymmetryResults();

  /// Maps a tolerance name ("tight", "normal", "loose", "veryloose") onto
  /// its preset, or nullptr when the name is not one of them.
  static msym::msym_thresholds_t* thresholdsForName(const QString& name);

  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;
  SymmetryWidget* m_symmetryWidget;

  QAction* m_viewSymmetryAction;

  msym::msym_context m_ctx;

  bool m_dirty = true;
};

inline QString Symmetry::description() const
{
  return tr("Provide symmetry functionality.");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SYMMETRY_H
