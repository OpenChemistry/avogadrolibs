/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/vibrations/vibrations.h"


namespace Avogadro::QtPlugins {

class VibrationsFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit VibrationsFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Vibrations(parent_);
    object->setObjectName("Vibrations");
    return object;
  }

  QString identifier() const override { return "Vibrations"; }

  QString description() const override { return "Vibrations"; }

};

} // namespace Avogadro::QtPlugins

#include "VibrationsPlugin.moc"
