/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "selectiontoolwidget.h"
#include "ui_selectiontoolwidget.h"

#include <QtWidgets/QColorDialog>

namespace Avogadro {
namespace QtPlugins {

SelectionToolWidget::SelectionToolWidget(QWidget* parent)
  : QWidget(parent), m_ui(new Ui::SelectionToolWidget)
{
  m_ui->setupUi(this);
  connect(m_ui->applyColorButton, SIGNAL(clicked()), this,
          SLOT(userClickedColor()));
}

SelectionToolWidget::~SelectionToolWidget()
{
  delete m_ui;
}

void SelectionToolWidget::setColor(Vector3ub color)
{
  QColor new_color(color[0], color[1], color[2]);
  QPalette pal = m_ui->applyColorButton->palette();
  pal.setColor(QPalette::Button, new_color);
  m_ui->applyColorButton->setPalette(pal);
  m_ui->applyColorButton->update();
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

} // namespace QtPlugins
} // namespace Avogadro
