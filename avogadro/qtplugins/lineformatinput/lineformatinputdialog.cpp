/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "lineformatinputdialog.h"
#include "ui_lineformatinputdialog.h"

#include <QtCore/QSettings>

namespace Avogadro::QtPlugins {

LineFormatInputDialog::LineFormatInputDialog(QWidget* aParent)
  : QDialog(aParent), m_ui(new Ui::LineFormatInputDialog)
{
  m_ui->setupUi(this);
}

LineFormatInputDialog::~LineFormatInputDialog()
{
  delete m_ui;
}

void LineFormatInputDialog::setFormats(const QStringList& indents)
{
  m_ui->formats->clear();
  m_ui->formats->addItems(indents);

  QSettings settings;
  QString lastUsed = settings.value("lineformatinput/lastUsed").toString();
  int index = m_ui->formats->findText(lastUsed);
  if (index >= 0)
    m_ui->formats->setCurrentIndex(index);
}

QString LineFormatInputDialog::format() const
{
  return m_ui->formats->currentText();
}

void LineFormatInputDialog::setCurrentFormat(const QString& format)
{
  int index = m_ui->formats->findText(format);
  if (index >= 0)
    m_ui->formats->setCurrentIndex(index);
}

QString LineFormatInputDialog::descriptor() const
{
  return m_ui->descriptor->text();
}

void LineFormatInputDialog::accept()
{
  QSettings settings;
  settings.setValue("lineformatinput/lastUsed", format());
  QDialog::accept();
}

} // namespace Avogadro
