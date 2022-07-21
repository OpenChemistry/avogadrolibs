/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_MOLECULARPROPERTIES_H
#define AVOGADRO_QTPLUGINS_MOLECULARPROPERTIES_H

#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {

namespace Core {
class Molecule;
}

namespace QtPlugins {
class MolecularPropertiesDialog;

/**
 * @brief The MolecularProperties class is an extension to launch
 * a MolecularPropertiesDialog.
 */
class MolecularProperties : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit MolecularProperties(QObject* parent_ = nullptr);
  ~MolecularProperties() override;

  QString name() const override { return tr("Molecular Properties"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

private slots:
  void showDialog();

private:
  QAction* m_action;
  MolecularPropertiesDialog* m_dialog;
  QtGui::Molecule* m_molecule;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_MOLECULARPROPERTIESEXTENSION_H
