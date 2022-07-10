/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_INSERTFRAGMENTDIALOG_H
#define AVOGADRO_QTPLUGINS_INSERTFRAGMENTDIALOG_H

#include <QtWidgets/QDialog>

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class InsertFragmentDialog;
}

/**
 * @brief Dialog to prompt a format and descriptor string.
 */
class InsertFragmentDialog : public QDialog
{
  Q_OBJECT

public:
  explicit InsertFragmentDialog(QWidget* parent = nullptr,
                                QString directory = "molecules",
                                Qt::WindowFlags f = 0);
  ~InsertFragmentDialog() override;

  QString fileName();

public Q_SLOTS:
  void refresh();

  void filterTextChanged(const QString &);

  void activated();

Q_SIGNALS:
  void performInsert(const QString &fileName, bool crystal);

private:
  Ui::InsertFragmentDialog* m_ui;

  class Private;
  Private *m_implementation;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_InsertFragmentDIALOG_H
