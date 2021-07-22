/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_PROPERTYTABLES_H
#define AVOGADRO_QTPLUGINS_PROPERTYTABLES_H

#include <avogadro/qtgui/extensionplugin.h>
namespace Avogadro {

namespace Core {
class Molecule;
}

namespace QtPlugins {

/**
 * @brief The PropertyTables class is an extension to launch
 * a "property table" views of the molecule.
 */
class PropertyTables : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit PropertyTables(QObject* parent_ = nullptr);
  ~PropertyTables() override;

  QString name() const override { return tr("PropertyTables"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

private slots:
  void showDialog();

private:
  QList<QAction *> m_actions;
  QtGui::Molecule* m_molecule;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_PROPERTYTABLES_H
