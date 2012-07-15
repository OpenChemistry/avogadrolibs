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

#ifndef AVOGADRO_QTPLUGINS_QUANTUMINPUT_H
#define AVOGADRO_QTPLUGINS_QUANTUMINPUT_H

#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {
namespace QtPlugins {

class QuantumInput : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit QuantumInput(QObject *parent = 0);
  ~QuantumInput();

  QString name() const { return tr("Quantum input"); }

  QString description() const { return tr("Generate input for quantum codes."); }

  QList<QAction *> actions() const;
  QStringList menuPath(QAction *) const;
};

class QuantumInputFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  EXTENSION_PLUGIN_FACTORY(QuantumInput, "Generate input for quantum codes")

  explicit QuantumInputFactory(QObject *parent_ = 0) : QObject(parent_) {}
};

}
}

#endif // AVOGADRO_QTPLUGINS_QUANTUMINPUT_H
