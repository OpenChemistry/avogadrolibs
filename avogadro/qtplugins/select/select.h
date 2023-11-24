/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SELECT_H
#define AVOGADRO_QTPLUGINS_SELECT_H

#include <avogadro/core/vector.h>
#include <avogadro/qtgui/extensionplugin.h>
#include <avogadro/qtgui/pluginlayermanager.h>

namespace Avogadro {

namespace QtGui {
class PeriodicTableView;
}
namespace QtPlugins {

/**
 * @brief The Select class is an extension to modify selections
 */
class Select : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit Select(QObject* parent_ = nullptr);
  ~Select() override;

  QString name() const override { return tr("Select"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

private slots:
  void selectAll();
  void selectNone();
  void invertSelection();
  void selectElement();
  void selectAtomIndex();
  void selectElement(int element);
  void selectResidue();

  void selectBackboneAtoms();
  void selectSidechainAtoms();

  void selectWater();
  bool isWaterOxygen(Index i);

  void enlargeSelection();
  void shrinkSelection();
  Vector3 getSelectionCenter();

  void createLayerFromSelection();

private:
  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;
  QtGui::PeriodicTableView* m_elements;
  QtGui::PluginLayerManager m_layerManager;

  bool evalSelect(bool input, Index index) const;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SELECT_H
