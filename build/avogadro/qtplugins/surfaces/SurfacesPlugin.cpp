/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/surfaces/surfaces.h"


namespace Avogadro::QtPlugins {

class SurfacesFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit SurfacesFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Surfaces(parent_);
    object->setObjectName("Surfaces");
    return object;
  }

  QString identifier() const override { return "Surfaces"; }

  QString description() const override { return "Surfaces"; }

};

} // namespace Avogadro::QtPlugins

#include "SurfacesPlugin.moc"
