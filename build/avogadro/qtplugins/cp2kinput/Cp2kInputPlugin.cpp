/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/cp2kinput/cp2kinput.h"


namespace Avogadro::QtPlugins {

class Cp2kInputFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit Cp2kInputFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Cp2kInput(parent_);
    object->setObjectName("Cp2kInput");
    return object;
  }

  QString identifier() const override { return "Cp2kInput"; }

  QString description() const override { return "CP2K input file generation"; }

};

} // namespace Avogadro::QtPlugins

#include "Cp2kInputPlugin.moc"
