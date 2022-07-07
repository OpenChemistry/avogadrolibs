/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "containerwidget.h"

#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QVBoxLayout>

namespace Avogadro::QtGui {

ContainerWidget::ContainerWidget(QWidget* p, Qt::WindowFlags f)
  : QWidget(p, f)
  , m_viewWidget(nullptr)
  , m_label(new QLabel(QStringLiteral("   "), this))
  , m_active(false)
{
  auto* h = new QHBoxLayout;
  h->setContentsMargins(0, 0, 0, 0);
  auto* v = new QVBoxLayout;
  v->setContentsMargins(0, 0, 0, 0);
  v->setSpacing(0);

  h->addWidget(m_label);
  h->addStretch();
  auto* button = new QPushButton(tr("Split Horizontal"), this);
  connect(button, SIGNAL(clicked()), SIGNAL(splitHorizontal()));
  h->addWidget(button);
  button = new QPushButton(tr("Split Vertical"), this);
  connect(button, SIGNAL(clicked()), SIGNAL(splitVertical()));
  h->addWidget(button);
  button = new QPushButton(tr("Close"), this);
  connect(button, SIGNAL(clicked()), SIGNAL(closeView()));
  h->addWidget(button);
  v->addLayout(h);
  setLayout(v);
}

ContainerWidget::~ContainerWidget() {}

void ContainerWidget::setViewWidget(QWidget* widget)
{
  if (m_viewWidget)
    m_viewWidget->deleteLater();
  m_viewWidget = widget;
  layout()->addWidget(widget);
}

QWidget* ContainerWidget::viewWidget()
{
  return m_viewWidget;
}

void ContainerWidget::setActive(bool active)
{
  if (m_active != active) {
    m_active = active;
    m_label->setText(active ? " * " : "   ");
  }
}

} // End Avogadro namespace
