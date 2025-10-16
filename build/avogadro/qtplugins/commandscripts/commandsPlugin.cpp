/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/commandscripts/command.h"


namespace Avogadro::QtPlugins {

class commandsFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit commandsFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Command(parent_);
    object->setObjectName("commands");
    return object;
  }

  QString identifier() const override { return "commands"; }

  QString description() const override { return "Script commands"; }

};

} // namespace Avogadro::QtPlugins

#include "commandsPlugin.moc"
