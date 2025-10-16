/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/insertfragment/insertfragment.h"


namespace Avogadro::QtPlugins {

class InsertFragmentFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit InsertFragmentFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new InsertFragment(parent_);
    object->setObjectName("InsertFragment");
    return object;
  }

  QString identifier() const override { return "InsertFragment"; }

  QString description() const override { return "Insert molecular fragments and crystals."; }

};

} // namespace Avogadro::QtPlugins

#include "InsertFragmentPlugin.moc"
