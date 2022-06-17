/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SUBMITCALCULATIONDIALOG_H
#define AVOGADRO_QTPLUGINS_SUBMITCALCULATIONDIALOG_H

#include <QDialog>

namespace Ui {
class SubmitCalculationDialog;
}

namespace Avogadro {
namespace QtPlugins {

class SubmitCalculationDialog : public QDialog
{
  Q_OBJECT

public:
  explicit SubmitCalculationDialog(QWidget* parent = nullptr);
  ~SubmitCalculationDialog();

  int exec() override;

  QString containerName() const;
  QString imageName() const;
  QVariantMap inputParameters() const;

private:
  QScopedPointer<Ui::SubmitCalculationDialog> m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SUBMITCALCULATIONDIALOG_H
