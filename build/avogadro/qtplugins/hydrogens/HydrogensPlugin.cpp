/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/hydrogens/hydrogens.h"


namespace Avogadro::QtPlugins {

class HydrogensFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit HydrogensFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Hydrogens(parent_);
    object->setObjectName("Hydrogens");
    return object;
  }

  QString identifier() const override { return "Hydrogens"; }

  QString description() const override { return "Extension that adds/removes hydrogens on a molecule."; }

};

} // namespace Avogadro::QtPlugins

#include "HydrogensPlugin.moc"
