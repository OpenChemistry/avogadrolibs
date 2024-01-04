/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CONFIGUREPYTHON_H
#define AVOGADRO_QTPLUGINS_CONFIGUREPYTHON_H

#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {
namespace QtPlugins {

class ConfigurePythonDialog;

/**
 * @brief Configure Python environment through a dialog.
 */
class ConfigurePython : public QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit ConfigurePython(QObject* parent_ = nullptr);
  ~ConfigurePython() override;

  QString name() const override { return tr("ConfigurePython"); }
  QString description() const override
  {
    return tr("Configure Python environments.");
  }
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

  QStringList pythonPaths() const;

  void setMolecule(QtGui::Molecule*) override {}

private slots:
  void showDialog();
  void accept();

private:
  QAction* m_action;
  ConfigurePythonDialog* m_dialog;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CONFIGUREPYTHON_H
