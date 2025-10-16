/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/centroid/centroid.h"


namespace Avogadro::QtPlugins {

class CentroidFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit CentroidFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Centroid(parent_);
    object->setObjectName("Centroid");
    return object;
  }

  QString identifier() const override { return "Centroid"; }

  QString description() const override { return "Add centroid and center-of-mass."; }

};

} // namespace Avogadro::QtPlugins

#include "CentroidPlugin.moc"
