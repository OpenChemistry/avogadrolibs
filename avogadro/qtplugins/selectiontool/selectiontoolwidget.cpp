/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "selectiontoolwidget.h"
#include "ui_selectiontoolwidget.h"

#include <QtWidgets/QColorDialog>

namespace Avogadro::QtPlugins {

SelectionToolWidget::SelectionToolWidget(QWidget* parent)
  : QWidget(parent), m_ui(new Ui::SelectionToolWidget)
{
  m_ui->setupUi(this);
  setDropDown(0, 1);
  connect(m_ui->applyColorButton, SIGNAL(clicked()), this,
          SLOT(userClickedColor()));
  connect(m_ui->changeLayerDropDown, SIGNAL(currentIndexChanged(int)), this,
          SIGNAL(changeLayer(int)));
}

SelectionToolWidget::~SelectionToolWidget()
{
  delete m_ui;
}

void SelectionToolWidget::setDropDown(size_t current, size_t max)
{
  m_ui->changeLayerDropDown->clear();
  for (size_t i = 0; i < max; ++i) {
    m_ui->changeLayerDropDown->addItem(QString::number(i + 1));
  }
  m_ui->changeLayerDropDown->addItem(tr("New Layer"));
  m_ui->changeLayerDropDown->setCurrentIndex(current);
}

void SelectionToolWidget::userClickedColor()
{
  QColorDialog dlg(this);

  QPalette pal = m_ui->applyColorButton->palette();
  dlg.setCurrentColor(pal.color(QPalette::Button));

  if (dlg.exec()) {
    QColor new_color = dlg.currentColor();
    pal.setColor(QPalette::Button, new_color);
    m_ui->applyColorButton->setPalette(pal);
    m_ui->applyColorButton->update();

    Vector3ub color;
    color[0] = static_cast<unsigned char>(new_color.red());
    color[1] = static_cast<unsigned char>(new_color.green());
    color[2] = static_cast<unsigned char>(new_color.blue());

    emit colorApplied(color);
  }
}

} // namespace Avogadro
