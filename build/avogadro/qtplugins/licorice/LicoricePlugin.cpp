/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/licorice/licorice.h"


namespace Avogadro::QtPlugins {

class LicoriceFactory : public QObject, public QtGui::ScenePluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ScenePluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ScenePluginFactory)

public:
  explicit LicoriceFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ScenePlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Licorice(parent_);
    object->setObjectName("Licorice");
    return object;
  }

  QString identifier() const override { return "Licorice"; }

  QString description() const override { return "Licorice rendering scheme"; }

};

} // namespace Avogadro::QtPlugins

#include "LicoricePlugin.moc"
