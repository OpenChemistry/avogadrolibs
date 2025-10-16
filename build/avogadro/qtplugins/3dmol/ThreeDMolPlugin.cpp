/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/3dmol/3dmol.h"


namespace Avogadro::QtPlugins {

class ThreeDMolFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit ThreeDMolFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new ThreeDMol(parent_);
    object->setObjectName("ThreeDMol");
    return object;
  }

  QString identifier() const override { return "ThreeDMol"; }

  QString description() const override { return "The 3DMol HTML Block Generator"; }

};

} // namespace Avogadro::QtPlugins

#include "ThreeDMolPlugin.moc"
