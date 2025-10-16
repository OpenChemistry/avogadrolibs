/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/insertdna/insertdna.h"


namespace Avogadro::QtPlugins {

class NucleicInputFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit NucleicInputFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new InsertDna(parent_);
    object->setObjectName("NucleicInput");
    return object;
  }

  QString identifier() const override { return "NucleicInput"; }

  QString description() const override { return "Insert DNA/RNA sequences."; }

};

} // namespace Avogadro::QtPlugins

#include "NucleicInputPlugin.moc"
