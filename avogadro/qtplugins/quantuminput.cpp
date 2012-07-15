/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "quantuminput.h"

#include <QtCore/QtPlugin>
#include <QtCore/QStringList>

namespace Avogadro {
namespace QtPlugins {

QuantumInput::QuantumInput(QObject *parent_) : ExtensionPlugin(parent_)
{
}

QuantumInput::~QuantumInput()
{
}

QList<QAction *> QuantumInput::actions() const
{
  return QList<QAction *>();
}

QStringList QuantumInput::menuPath(QAction *) const
{
  QStringList path;
  path << tr("&Extensions") << tr("&NWChem");
  return path;
}

}
}

Q_EXPORT_PLUGIN2(quantuminput, Avogadro::QtPlugins::QuantumInputFactory)
