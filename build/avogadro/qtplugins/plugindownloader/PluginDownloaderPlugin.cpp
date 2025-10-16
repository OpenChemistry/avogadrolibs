/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/plugindownloader/plugindownloader.h"


namespace Avogadro::QtPlugins {

class PluginDownloaderFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit PluginDownloaderFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new PluginDownloader(parent_);
    object->setObjectName("PluginDownloader");
    return object;
  }

  QString identifier() const override { return "PluginDownloader"; }

  QString description() const override { return "Download plugins from Github repositories"; }

};

} // namespace Avogadro::QtPlugins

#include "PluginDownloaderPlugin.moc"
