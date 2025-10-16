/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/spacegroup/spacegroup.h"


namespace Avogadro::QtPlugins {

class SpaceGroupFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit SpaceGroupFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new SpaceGroup(parent_);
    object->setObjectName("SpaceGroup");
    return object;
  }

  QString identifier() const override { return "SpaceGroup"; }

  QString description() const override { return "Space group features for crystals."; }

};

} // namespace Avogadro::QtPlugins

#include "SpaceGroupPlugin.moc"
