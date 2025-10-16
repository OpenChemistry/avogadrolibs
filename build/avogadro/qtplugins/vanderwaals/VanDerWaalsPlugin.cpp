/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/vanderwaals/vanderwaals.h"


namespace Avogadro::QtPlugins {

class VanDerWaalsFactory : public QObject, public QtGui::ScenePluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ScenePluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ScenePluginFactory)

public:
  explicit VanDerWaalsFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ScenePlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new VanDerWaals(parent_);
    object->setObjectName("VanDerWaals");
    return object;
  }

  QString identifier() const override { return "VanDerWaals"; }

  QString description() const override { return "Van der Waals rendering scheme"; }

};

} // namespace Avogadro::QtPlugins

#include "VanDerWaalsPlugin.moc"
