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

#ifndef AVOGADRO_QTPLUGINS_SELECTIONTOOLWIDGET_H
#define AVOGADRO_QTPLUGINS_SELECTIONTOOLWIDGET_H

#include <QtWidgets/QWidget>

#include <avogadro/core/vector.h>

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class SelectionToolWidget;
}

class SelectionToolWidget : public QWidget
{
  Q_OBJECT

public:
  explicit SelectionToolWidget(QWidget* parent = nullptr);
  ~SelectionToolWidget();

  void setColor(Vector3ub color);

signals:
  void colorApplied(Vector3ub color);

private slots:
  void userClickedColor();

private:
  Ui::SelectionToolWidget* m_ui;
  Vector3ub m_currentColor;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SELECTIONTOOLWIDGET_H
