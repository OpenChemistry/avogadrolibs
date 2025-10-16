/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/focus/focus.h"


namespace Avogadro::QtPlugins {

class FocusFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit FocusFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Focus(parent_);
    object->setObjectName("Focus");
    return object;
  }

  QString identifier() const override { return "Focus"; }

  QString description() const override { return "Focus the view on specific features."; }

};

} // namespace Avogadro::QtPlugins

#include "FocusPlugin.moc"
