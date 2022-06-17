/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CONFIGDIALOG_H
#define AVOGADRO_QTPLUGINS_CONFIGDIALOG_H

#include <QDialog>
#include <QScopedPointer>

namespace Ui {
class ConfigDialog;
}

namespace Avogadro {
namespace QtPlugins {

class ConfigDialog : public QDialog
{
  Q_OBJECT

public:
  explicit ConfigDialog(QWidget* parent = nullptr);
  ~ConfigDialog();

  void setGirderUrl(const QString& url);
  void setApiKey(const QString& apiKey);

  QString girderUrl() const;
  QString apiKey() const;

private:
  QScopedPointer<Ui::ConfigDialog> m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CONFIGDIALOG_H
