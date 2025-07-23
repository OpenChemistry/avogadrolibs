/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "extensionplugin.h"

#include <QWidget>

namespace Avogadro::QtGui {

ExtensionPlugin::ExtensionPlugin(QObject* parent_) : QObject(parent_) {}

ExtensionPlugin::~ExtensionPlugin() {}

QList<Io::FileFormat*> ExtensionPlugin::fileFormats() const
{
  return QList<Io::FileFormat*>();
}

ExtensionPluginFactory::~ExtensionPluginFactory() {}

bool ExtensionPlugin::readMolecule(Molecule&)
{
  return false;
}

void ExtensionPlugin::setScene(Rendering::Scene*) {}

void ExtensionPlugin::setCamera([[maybe_unused]] Rendering::Camera* camera) {}

void ExtensionPlugin::setActiveWidget(QWidget* widget)
{
  setParent(widget);
}

bool ExtensionPlugin::handleCommand(const QString& command,
                                    const QVariantMap& options)
{
  Q_UNUSED(command);
  Q_UNUSED(options);
  return false;
}

} // namespace Avogadro::QtGui
