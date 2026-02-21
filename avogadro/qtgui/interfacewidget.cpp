/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "interfacewidget.h"

#include <avogadro/qtgui/filebrowsewidget.h>
#include <avogadro/qtgui/molecule.h>

#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QTextEdit>

#include <QtCore/QDebug>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QPointer>
#include <QtCore/QSettings>
#include <QtCore/QTimer>

namespace Avogadro::QtGui {

InterfaceWidget::InterfaceWidget(const QString& scriptFilePath,
                                 QWidget* parent_)
  : JsonWidget(parent_), m_interfaceScript(QString())
{
  if (!scriptFilePath.isEmpty())
    this->setInterfaceScript(scriptFilePath);
}

InterfaceWidget::~InterfaceWidget() {}

void InterfaceWidget::setInterfaceScript(const QString& scriptFile)
{
  m_interfaceScript.setScriptFilePath(scriptFile);
  m_options = m_interfaceScript.options();
  updateOptions();
}

void InterfaceWidget::reloadOptions()
{
  m_options = m_interfaceScript.options();
  updateOptions();
}

void InterfaceWidget::defaultsClicked()
{
  setOptionDefaults();
}

void InterfaceWidget::setWarningText(const QString& warn)
{
  qWarning() << tr("Script returns warnings:\n") << warn;
}

QString InterfaceWidget::warningText() const
{
  return QString();
}

void InterfaceWidget::showError(const QString& err)
{
  qWarning() << err;

  QWidget* theParent =
    this->isVisible() ? this : qobject_cast<QWidget*>(parent());
  QDialog dlg(theParent);
  auto* vbox = new QVBoxLayout();
  auto* label = new QLabel(tr("An error has occurred:"));
  vbox->addWidget(label);
  auto* textBrowser = new QTextBrowser();

  // adjust the size of the text browser to ~80 char wide, ~20 lines high
  QSize theSize = textBrowser->sizeHint();
  QFontMetrics metrics(textBrowser->currentFont());
  int charWidth = metrics.horizontalAdvance(QStringLiteral("i7OPlmWn9/")) / 10;
  int charHeight = metrics.lineSpacing();
  theSize.setWidth(80 * charWidth);
  theSize.setHeight(20 * charHeight);
  textBrowser->setMinimumSize(theSize);
  textBrowser->setText(err);
  vbox->addWidget(textBrowser);
  dlg.setLayout(vbox);

  dlg.exec();
}

QString InterfaceWidget::settingsKey(const QString& identifier) const
{
  return QStringLiteral("scriptPlugin/%1/%2")
    .arg(m_interfaceScript.displayName(), identifier);
}

} // namespace Avogadro::QtGui
