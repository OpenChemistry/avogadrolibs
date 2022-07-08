/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "configdialog.h"
#include "ui_configdialog.h"

namespace Avogadro::QtPlugins {

ConfigDialog::ConfigDialog(QWidget* parent)
  : QDialog(parent), m_ui(new Ui::ConfigDialog)
{
  m_ui->setupUi(this);
}

ConfigDialog::~ConfigDialog() = default;

void ConfigDialog::setGirderUrl(const QString& girderUrl)
{
  m_ui->girderUrl->setText(girderUrl);
}

void ConfigDialog::setApiKey(const QString& apiKey)
{
  m_ui->apiKey->setText(apiKey);
}

QString ConfigDialog::girderUrl() const
{
  QString url = m_ui->girderUrl->text();
  if (!url.endsWith("/api/v1")) {
    // Append this automatically...
    url += "/api/v1";
  }
  return url;
}

QString ConfigDialog::apiKey() const
{
  return m_ui->apiKey->text();
}

} // namespace Avogadro
