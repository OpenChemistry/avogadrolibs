/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/propertytables/propertytables.h"


namespace Avogadro::QtPlugins {

class PropertyTablesFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit PropertyTablesFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new PropertyTables(parent_);
    object->setObjectName("PropertyTables");
    return object;
  }

  QString identifier() const override { return "PropertyTables"; }

  QString description() const override { return "Atom, Bond, Angle, Dihedral property tables."; }

};

} // namespace Avogadro::QtPlugins

#include "PropertyTablesPlugin.moc"
