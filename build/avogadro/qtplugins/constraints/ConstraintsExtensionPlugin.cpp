/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/constraints/constraintsextension.h"


namespace Avogadro::QtPlugins {

class ConstraintsExtensionFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit ConstraintsExtensionFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new ConstraintsExtension(parent_);
    object->setObjectName("ConstraintsExtension");
    return object;
  }

  QString identifier() const override { return "ConstraintsExtension"; }

  QString description() const override { return "Constraints extension"; }

};

} // namespace Avogadro::QtPlugins

#include "ConstraintsExtensionPlugin.moc"
