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

#include "multiviewwidget.h"
#include "containerwidget.h"
#include "viewfactory.h"

#include <QtWidgets/QSplitter>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QPushButton>
#include <QtCore/QEvent>

namespace Avogadro {
namespace QtGui {

class ActiveWidgetFilter : public QObject
{
  Q_OBJECT

public:
  ActiveWidgetFilter(MultiViewWidget *p = 0) : QObject(p), m_widget(p) {}

signals:
  void activeWidget(QWidget *widget);

protected:
  bool eventFilter(QObject *obj, QEvent *e)
  {
    Q_ASSERT(m_widget);
    if (e->type() == QEvent::MouseButtonPress) {
      QWidget *w = qobject_cast<QWidget *>(obj);
      if (w)
        m_widget->setActiveWidget(w);
    }
    return QObject::eventFilter(obj, e);
  }
  MultiViewWidget* m_widget;
};

MultiViewWidget::MultiViewWidget(QWidget *p, Qt::WindowFlags f)
  : QWidget(p, f), m_factory(NULL), m_activeWidget(NULL),
    m_activeFilter(new ActiveWidgetFilter(this))
{
}

MultiViewWidget::~MultiViewWidget()
{
}

void MultiViewWidget::addWidget(QWidget *widget)
{
  if (widget) {
    ContainerWidget *container = createContainer(widget);
    m_children << container;
    if (m_children.size() == 1) {
      QVBoxLayout *widgetLayout = qobject_cast<QVBoxLayout *>(layout());
      if (!widgetLayout) {
        widgetLayout = new QVBoxLayout;
        widgetLayout->setContentsMargins(0, 0, 0, 0);
        setLayout(widgetLayout);
      }
      widgetLayout->addWidget(container);
    }
    widget->installEventFilter(m_activeFilter);
    setActiveWidget(widget);
  }
}

QWidget * MultiViewWidget::activeWidget()
{
  if (m_children.empty())
    return NULL;

  return m_children.first();
}

void MultiViewWidget::setActiveWidget(QWidget *widget)
{
  if (m_activeWidget != widget) {
    ContainerWidget *container(NULL);
    if (m_activeWidget)
      container = qobject_cast<ContainerWidget *>(m_activeWidget->parentWidget());
    if (container)
      container->setActive(false);
    m_activeWidget = widget;
    container = NULL;
    if (widget)
      container = qobject_cast<ContainerWidget *>(widget->parentWidget());
    if (container)
      container->setActive(true);
    emit activeWidgetChanged(widget);
  }
}

void MultiViewWidget::splitHorizontal()
{
  ContainerWidget *container = qobject_cast<ContainerWidget *>(sender());
  if (container)
    splitView(Qt::Horizontal, container);
}

void MultiViewWidget::splitVertical()
{
  ContainerWidget *container = qobject_cast<ContainerWidget *>(sender());
  if (container)
    splitView(Qt::Vertical, container);
}

void MultiViewWidget::createView()
{
  QPushButton *button = qobject_cast<QPushButton *>(sender());
  if (m_factory && button && button->parentWidget()
      && button->parentWidget()->parentWidget()) {
    QWidget *optionsWidget = button->parentWidget();
    ContainerWidget *container
        = qobject_cast<ContainerWidget *>(optionsWidget->parentWidget());
    if (container) {
      QWidget *widget = m_factory->createView(button->text());
      if (widget) {
        widget->installEventFilter(m_activeFilter);
        container->layout()->removeWidget(optionsWidget);
        container->layout()->addWidget(widget);
        optionsWidget->deleteLater();
        setActiveWidget(widget);
      }
    }
  }
}

ContainerWidget * MultiViewWidget::createContainer(QWidget *widget)
{
  ContainerWidget *container = new ContainerWidget;
  connect(container, SIGNAL(splitHorizontal()), SLOT(splitHorizontal()));
  connect(container, SIGNAL(splitVertical()), SLOT(splitVertical()));

  if (widget) {
    container->setViewWidget(widget);
  }
  // If we have a factory, then create the options widget too!
  else if (m_factory) {
    QWidget *optionsWidget = new QWidget;
    QVBoxLayout *v = new QVBoxLayout;
    optionsWidget->setLayout(v);
    v->addStretch();
    foreach (const QString &name, m_factory->views()) {
      QPushButton *button = new QPushButton(name);
      button->setToolTip(tr("Create a new view"));
      connect(button, SIGNAL(clicked()), SLOT(createView()));
      QHBoxLayout *h = new QHBoxLayout;
      h->addStretch();
      h->addWidget(button);
      h->addStretch();
      v->addLayout(h);
    }
    v->addStretch();
    container->layout()->addWidget(optionsWidget);
  }

  return container;
}

void MultiViewWidget::splitView(Qt::Orientation orient,
                                ContainerWidget *container)
{
  QVBoxLayout *widgetLayout = qobject_cast<QVBoxLayout *>(container->parent());
  QSplitter *split = qobject_cast<QSplitter *>(container->parent());
  if (!widgetLayout)
    if (container->parent() == this)
      widgetLayout = qobject_cast<QVBoxLayout *>(layout());
  if (widgetLayout) {
    QSplitter *splitter = new QSplitter(orient, this);
    widgetLayout->removeWidget(container);
    widgetLayout->addWidget(splitter);
    splitter->addWidget(container);
    container = createContainer();
    splitter->addWidget(container);
  }
  else if (split) {
    QSplitter *splitter = new QSplitter(orient, this);
    int idx = split->indexOf(container);
    splitter->addWidget(container);
    container = createContainer();
    splitter->addWidget(container);
    split->insertWidget(idx, splitter);
  }
}

} // End QtGui namespace
} // End Avogadro namespace

#include "multiviewwidget.moc"
