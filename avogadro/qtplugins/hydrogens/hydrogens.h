/******************************************************************************
  This source file is part of the MoleQueue project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_HYDROGENS_H
#define AVOGADRO_QTPLUGINS_HYDROGENS_H

#include <avogadro/qtgui/extensionplugin.h>
#include <avogadro/qtgui/hydrogentools.h>

namespace Avogadro::QtPlugins {

/**
 * @brief The Hydrogens class is an extension to modify hydrogens.
 */
class Hydrogens : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit Hydrogens(QObject* parent_ = nullptr);
  ~Hydrogens() override;

  QString name() const override { return tr("Hydrogens"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

  bool handleCommand(const QString& command,
                     const QVariantMap& options) override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

private slots:
  void adjustHydrogens();
  void addHydrogens();
  void removeHydrogens();
  void removeAllHydrogens();

private:
  void registerHydrogensCommands();

  /** Apply @p adjustment as one undo step and emit the changes.
   *  @return How many hydrogens were added and removed. */
  QtGui::HydrogenTools::HydrogenCounts applyAdjustment(
    QtGui::HydrogenTools::Adjustment adjustment);
  /** Remove every hydrogen as one undo step and emit the changes. */
  QtGui::HydrogenTools::HydrogenCounts applyRemoveAll();

  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;
};

} // namespace Avogadro::QtPlugins

#endif // AVOGADRO_QTPLUGINS_HYDROGENS_H
