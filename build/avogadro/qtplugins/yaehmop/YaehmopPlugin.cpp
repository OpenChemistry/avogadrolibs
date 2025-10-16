/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/yaehmop/yaehmop.h"


namespace Avogadro::QtPlugins {

class YaehmopFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit YaehmopFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Yaehmop(parent_);
    object->setObjectName("Yaehmop");
    return object;
  }

  QString identifier() const override { return "Yaehmop"; }

  QString description() const override { return "Use yaehmop to perform extended Hückel calculations."; }

};

} // namespace Avogadro::QtPlugins

#include "YaehmopPlugin.moc"
