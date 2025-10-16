/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/dipole/dipole.h"


namespace Avogadro::QtPlugins {

class DipoleFactory : public QObject, public QtGui::ScenePluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ScenePluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ScenePluginFactory)

public:
  explicit DipoleFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ScenePlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Dipole(parent_);
    object->setObjectName("Dipole");
    return object;
  }

  QString identifier() const override { return "Dipole"; }

  QString description() const override { return "Dipole rendering scheme"; }

};

} // namespace Avogadro::QtPlugins

#include "DipolePlugin.moc"
