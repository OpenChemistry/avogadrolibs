/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_ZMATRIXEDITOR_H
#define AVOGADRO_QTPLUGINS_ZMATRIXEDITOR_H

#include <avogadro/qtgui/extensionplugin.h>

#include <QtCore/QPointer>

class QDockWidget;
class QLabel;
class QPushButton;

namespace Avogadro {
namespace QtPlugins {

class ZMatrixModel;
class ZMatrixView;

/**
 * @brief A dockable table of the molecule's internal coordinates.
 */
class ZMatrixEditor : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit ZMatrixEditor(QObject* parent = nullptr);
  ~ZMatrixEditor() override;

  QString name() const override { return tr("Z-Matrix Editor"); }
  QString description() const override
  {
    return tr("Edit bond lengths, angles and torsions in a table.");
  }

  QList<QAction*> actions() const override;
  QStringList menuPath(QAction* action = nullptr) const override;
  QList<QDockWidget*> dockWidgets() const override;

public slots:
  void setMolecule(QtGui::Molecule* molecule) override;

private slots:
  void reorderAtoms();
  void rebuildGeometry();
  void showMessage(const QString& message);
  void updateButtons();

private:
  void buildDock();

  // The dock is handed to the application, which reparents it and takes
  // ownership. Held by QPointer so that the destructor can tell whether that
  // happened and clean up if it did not.
  QPointer<QDockWidget> m_dock;
  ZMatrixView* m_view = nullptr;
  ZMatrixModel* m_model = nullptr;
  QPushButton* m_reorderButton = nullptr;
  QPushButton* m_rebuildButton = nullptr;
  QLabel* m_message = nullptr;
  QAction* m_action = nullptr;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_ZMATRIXEDITOR_H
