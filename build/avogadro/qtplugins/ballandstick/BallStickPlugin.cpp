/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/ballandstick/ballandstick.h"


namespace Avogadro::QtPlugins {

class BallStickFactory : public QObject, public QtGui::ScenePluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ScenePluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ScenePluginFactory)

public:
  explicit BallStickFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ScenePlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new BallAndStick(parent_);
    object->setObjectName("BallStick");
    return object;
  }

  QString identifier() const override { return "BallStick"; }

  QString description() const override { return "Ball and stick rendering scheme"; }

};

} // namespace Avogadro::QtPlugins

#include "BallStickPlugin.moc"
