/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/navigator/navigator.h"


namespace Avogadro::QtPlugins {

class NavigatorFactory : public QObject, public QtGui::ToolPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ToolPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ToolPluginFactory)

public:
  explicit NavigatorFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ToolPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Navigator(parent_);
    object->setObjectName("Navigator");
    return object;
  }

  QString identifier() const override { return "Navigator"; }

  QString description() const override { return "Navigation tool"; }

};

} // namespace Avogadro::QtPlugins

#include "NavigatorPlugin.moc"
