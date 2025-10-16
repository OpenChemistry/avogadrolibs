/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/svg/svg.h"


namespace Avogadro::QtPlugins {

class SVGFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit SVGFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new SVG(parent_);
    object->setObjectName("SVG");
    return object;
  }

  QString identifier() const override { return "SVG"; }

  QString description() const override { return "Project the screen in a SVG image."; }

};

} // namespace Avogadro::QtPlugins

#include "SVGPlugin.moc"
