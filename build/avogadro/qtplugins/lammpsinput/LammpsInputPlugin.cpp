/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/lammpsinput/lammpsinput.h"


namespace Avogadro::QtPlugins {

class LammpsInputFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit LammpsInputFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new LammpsInput(parent_);
    object->setObjectName("LammpsInput");
    return object;
  }

  QString identifier() const override { return "LammpsInput"; }

  QString description() const override { return "LAMMPS input file generation"; }

};

} // namespace Avogadro::QtPlugins

#include "LammpsInputPlugin.moc"
