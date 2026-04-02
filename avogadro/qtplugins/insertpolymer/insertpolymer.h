/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_INSERTPOLYMER_H
#define AVOGADRO_QTPLUGINS_INSERTPOLYMER_H

#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {
namespace QtPlugins {

class InsertPolymerDialog;

class InsertPolymer : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit InsertPolymer(QObject* parent = nullptr);
  ~InsertPolymer() override;

  QString name() const override { return tr("Insert Polymer"); }
  QString description() const override
  {
    return tr("Build polymers from monomer repeat units.");
  }

  QList<QAction*> actions() const override;
  QStringList menuPath(QAction* action = nullptr) const override;

  void setMolecule(QtGui::Molecule* mol) override;

public slots:
  void showDialog();
  void buildPolymer(const QString& smiles);

private:
  QtGui::Molecule* m_molecule;
  InsertPolymerDialog* m_dialog;
  QList<QAction*> m_actions;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_INSERTPOLYMER_H
