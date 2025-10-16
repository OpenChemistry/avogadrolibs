/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/surfacerender/surfacerender.h"


namespace Avogadro::QtPlugins {

class SurfaceRenderFactory : public QObject, public QtGui::ScenePluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ScenePluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ScenePluginFactory)

public:
  explicit SurfaceRenderFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ScenePlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new SurfaceRender(parent_);
    object->setObjectName("SurfaceRender");
    return object;
  }

  QString identifier() const override { return "SurfaceRender"; }

  QString description() const override { return "Surface and mesh rendering"; }

};

} // namespace Avogadro::QtPlugins

#include "SurfaceRenderPlugin.moc"
