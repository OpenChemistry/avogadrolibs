/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_LINEFORMATINPUTDIALOG_H
#define AVOGADRO_QTPLUGINS_LINEFORMATINPUTDIALOG_H

#include <QtWidgets/QDialog>

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class LineFormatInputDialog;
}

/**
 * @brief Dialog to prompt a format and descriptor string.
 */
class LineFormatInputDialog : public QDialog
{
  Q_OBJECT

public:
  explicit LineFormatInputDialog(QWidget* parent = nullptr);
  ~LineFormatInputDialog() override;

  void setFormats(const QStringList& indents);
  QString format() const;

  void setCurrentFormat(const QString& format);

  QString descriptor() const;

protected slots:
  void accept() override;

private:
  Ui::LineFormatInputDialog* m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_LINEFORMATINPUTDIALOG_H
