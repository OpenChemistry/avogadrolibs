/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2007 Donald Ephraim Curtis
  Copyright 2010 Eric C. Brown
  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef QTAIMENGINE_H
#define QTAIMENGINE_H

#include <avogadro/qtgui/sceneplugin.h>

#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace QtPlugins {

class QTAIMEngine : public QtGui::ScenePlugin
{
  Q_OBJECT
public:
  explicit QTAIMEngine(QObject* parent = nullptr);
  virtual ~QTAIMEngine() override;

  void process(const Core::Molecule& molecule,
               Rendering::GroupNode& node) override;

  QString name() const override { return tr("QTAIM"); }

  QString description() const override
  {
    return tr("Renders primitives using QTAIM properties");
  }

  bool isEnabled() const override { return m_enabled; }

  void setEnabled(bool enable) override { m_enabled = enable; }

private:
  bool m_enabled;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif
