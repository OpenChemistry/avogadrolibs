/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/cartoons/cartoons.h"


namespace Avogadro::QtPlugins {

class CartoonsFactory : public QObject, public QtGui::ScenePluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ScenePluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ScenePluginFactory)

public:
  explicit CartoonsFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ScenePlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Cartoons(parent_);
    object->setObjectName("Cartoons");
    return object;
  }

  QString identifier() const override { return "Cartoons"; }

  QString description() const override { return "Cartoon family rendering scheme"; }

};

} // namespace Avogadro::QtPlugins

#include "CartoonsPlugin.moc"
