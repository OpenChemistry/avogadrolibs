/******************************************************************************
  This source file is part of the MoleQueue project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_HYDROGENS_H
#define AVOGADRO_QTPLUGINS_HYDROGENS_H

#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {
namespace QtPlugins {

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

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

private slots:
  void adjustHydrogens();
  void addHydrogens();
  void removeHydrogens();
  void removeAllHydrogens();

private:
  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_HYDROGENS_H
