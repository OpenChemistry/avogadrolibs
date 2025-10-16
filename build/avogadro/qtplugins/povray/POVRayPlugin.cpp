/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/povray/povray.h"


namespace Avogadro::QtPlugins {

class POVRayFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit POVRayFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new POVRay(parent_);
    object->setObjectName("POVRay");
    return object;
  }

  QString identifier() const override { return "POVRay"; }

  QString description() const override { return "Render the scene using POV-Ray."; }

};

} // namespace Avogadro::QtPlugins

#include "POVRayPlugin.moc"
