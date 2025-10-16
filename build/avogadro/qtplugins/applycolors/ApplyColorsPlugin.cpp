/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/applycolors/applycolors.h"


namespace Avogadro::QtPlugins {

class ApplyColorsFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit ApplyColorsFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new ApplyColors(parent_);
    object->setObjectName("ApplyColors");
    return object;
  }

  QString identifier() const override { return "ApplyColors"; }

  QString description() const override { return "Extension to apply color schemes to atoms and residues."; }

};

} // namespace Avogadro::QtPlugins

#include "ApplyColorsPlugin.moc"
