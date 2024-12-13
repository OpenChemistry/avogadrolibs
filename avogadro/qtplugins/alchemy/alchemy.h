/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_ALCHEMY_H
#define AVOGADRO_QTPLUGINS_ALCHEMY_H

#include <avogadro/core/avogadrocore.h>
#include <avogadro/qtgui/extensionplugin.h>

#include <QtWidgets/QDialog>

namespace Ui {
class BondingDialog;
}

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The Bonding class performs bonding operations on demand.
 */
class Alchemy : public QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit Alchemy(QObject* parent_ = nullptr);
  ~Alchemy() override;

  QString name() const override { return tr("Alchemy"); }

  QString description() const override
  {
    return tr("Change elements of atoms.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction* action) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

private slots:
  void changeElements();

private:
  QtGui::Molecule* m_molecule;

  QAction* m_action;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_ALCHEMY_H
