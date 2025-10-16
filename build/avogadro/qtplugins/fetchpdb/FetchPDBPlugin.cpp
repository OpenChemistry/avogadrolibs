/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/fetchpdb/fetchpdb.h"


namespace Avogadro::QtPlugins {

class FetchPDBFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit FetchPDBFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new FetchPDB(parent_);
    object->setObjectName("FetchPDB");
    return object;
  }

  QString identifier() const override { return "FetchPDB"; }

  QString description() const override { return "Fetch PDB"; }

};

} // namespace Avogadro::QtPlugins

#include "FetchPDBPlugin.moc"
