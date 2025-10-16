/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/vrml/vrml.h"


namespace Avogadro::QtPlugins {

class VRMLFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit VRMLFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new VRML(parent_);
    object->setObjectName("VRML");
    return object;
  }

  QString identifier() const override { return "VRML"; }

  QString description() const override { return "Render the scene using VRML."; }

};

} // namespace Avogadro::QtPlugins

#include "VRMLPlugin.moc"
