/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/ply/ply.h"


namespace Avogadro::QtPlugins {

class PLYFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit PLYFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new PLY(parent_);
    object->setObjectName("PLY");
    return object;
  }

  QString identifier() const override { return "PLY"; }

  QString description() const override { return "Render the scene using PLY."; }

};

} // namespace Avogadro::QtPlugins

#include "PLYPlugin.moc"
