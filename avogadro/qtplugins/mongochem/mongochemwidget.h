/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2019 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_MONGOCHEMWIDGET_H
#define AVOGADRO_QTPLUGINS_MONGOCHEMWIDGET_H

#include <memory>

#include <QWidget>

namespace Avogadro {

namespace QtPlugins {

class MongoChemWidget : public QWidget
{
  Q_OBJECT

public:
  explicit MongoChemWidget(QWidget* parent = nullptr);
  ~MongoChemWidget() override;

private:
  class Impl;
  std::unique_ptr<Impl> m_impl;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_MONGOCHEMWIDGET_H
