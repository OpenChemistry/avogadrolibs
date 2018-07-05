/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2014 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "containerwidget.h"

#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QVBoxLayout>

namespace Avogadro {
namespace QtGui {

ContainerWidget::ContainerWidget(QWidget* p, Qt::WindowFlags f)
  : QWidget(p, f)
  , m_viewWidget(nullptr)
  , m_label(new QLabel(QStringLiteral("   "), this))
  , m_active(false)
{
  QHBoxLayout* h = new QHBoxLayout;
  h->setContentsMargins(0, 0, 0, 0);
  QVBoxLayout* v = new QVBoxLayout;
  v->setContentsMargins(0, 0, 0, 0);
  v->setSpacing(0);

  h->addWidget(m_label);
  h->addStretch();
  QPushButton* button = new QPushButton(tr("Split Horizontal"), this);
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

} // End QtGui namespace
} // End Avogadro namespace
