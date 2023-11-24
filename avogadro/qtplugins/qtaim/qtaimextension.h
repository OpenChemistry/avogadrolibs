/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef QTAIMEXTENSION_H
#define QTAIMEXTENSION_H

#include <avogadro/qtgui/extensionplugin.h>

#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace QtPlugins {

class QTAIMExtension : public QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit QTAIMExtension(QObject* parent = nullptr);
  ~QTAIMExtension() override;

  QString name() const override { return tr("QTAIM"); }
  QString description() const override { return tr("QTAIM extension"); }
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction* action) const override;

public slots:
  void setMolecule(QtGui::Molecule* molecule) override;

private slots:
  void triggered();

private:
  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // QTAIMEXTENSION_H
