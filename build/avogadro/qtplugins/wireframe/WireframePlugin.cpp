/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/wireframe/wireframe.h"


namespace Avogadro::QtPlugins {

class WireframeFactory : public QObject, public QtGui::ScenePluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ScenePluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ScenePluginFactory)

public:
  explicit WireframeFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ScenePlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Wireframe(parent_);
    object->setObjectName("Wireframe");
    return object;
  }

  QString identifier() const override { return "Wireframe"; }

  QString description() const override { return "Wireframe rendering scheme"; }

};

} // namespace Avogadro::QtPlugins

#include "WireframePlugin.moc"
