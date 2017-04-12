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

#include "extensionplugin.h"

namespace Avogadro {
namespace QtGui {

ExtensionPlugin::ExtensionPlugin(QObject* parent_) : QObject(parent_)
{
}

ExtensionPlugin::~ExtensionPlugin()
{
}

QList<Io::FileFormat*> ExtensionPlugin::fileFormats() const
{
  return QList<Io::FileFormat*>();
}

ExtensionPluginFactory::~ExtensionPluginFactory()
{
}

bool ExtensionPlugin::readMolecule(Molecule&)
{
  return false;
}

void ExtensionPlugin::setScene(Rendering::Scene*)
{
}

void ExtensionPlugin::setCamera(Rendering::Camera* camera)
{
}

void ExtensionPlugin::setActiveWidget(QWidget* widget)
{
}

} // End QtGui namespace
} // End Avogadro namespace
