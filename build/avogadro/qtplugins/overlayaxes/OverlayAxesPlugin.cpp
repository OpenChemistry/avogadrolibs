/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/overlayaxes/overlayaxes.h"


namespace Avogadro::QtPlugins {

class OverlayAxesFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit OverlayAxesFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new OverlayAxes(parent_);
    object->setObjectName("OverlayAxes");
    return object;
  }

  QString identifier() const override { return "OverlayAxes"; }

  QString description() const override { return "Reference Axes Overlay"; }

};

} // namespace Avogadro::QtPlugins

#include "OverlayAxesPlugin.moc"
