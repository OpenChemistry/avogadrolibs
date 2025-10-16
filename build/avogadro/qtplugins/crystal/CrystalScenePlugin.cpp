/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/crystal/crystalscene.h"


namespace Avogadro::QtPlugins {

class CrystalSceneFactory : public QObject, public QtGui::ScenePluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ScenePluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ScenePluginFactory)

public:
  explicit CrystalSceneFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ScenePlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new CrystalScene(parent_);
    object->setObjectName("CrystalScene");
    return object;
  }

  QString identifier() const override { return "CrystalScene"; }

  QString description() const override { return "Render unit cell lattice."; }

};

} // namespace Avogadro::QtPlugins

#include "CrystalScenePlugin.moc"
