/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/resetview/resetview.h"


namespace Avogadro::QtPlugins {

class ResetViewFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit ResetViewFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new ResetView(parent_);
    object->setObjectName("ResetView");
    return object;
  }

  QString identifier() const override { return "ResetView"; }

  QString description() const override { return "Manipulate the view camera."; }

};

} // namespace Avogadro::QtPlugins

#include "ResetViewPlugin.moc"
