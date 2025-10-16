/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/force/force.h"


namespace Avogadro::QtPlugins {

class ForceFactory : public QObject, public QtGui::ScenePluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ScenePluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ScenePluginFactory)

public:
  explicit ForceFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ScenePlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Force(parent_);
    object->setObjectName("Force");
    return object;
  }

  QString identifier() const override { return "Force"; }

  QString description() const override { return "Force rendering scheme"; }

};

} // namespace Avogadro::QtPlugins

#include "ForcePlugin.moc"
