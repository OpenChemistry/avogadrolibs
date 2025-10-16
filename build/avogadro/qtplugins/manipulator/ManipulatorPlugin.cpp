/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/manipulator/manipulator.h"


namespace Avogadro::QtPlugins {

class ManipulatorFactory : public QObject, public QtGui::ToolPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ToolPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ToolPluginFactory)

public:
  explicit ManipulatorFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ToolPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Manipulator(parent_);
    object->setObjectName("Manipulator");
    return object;
  }

  QString identifier() const override { return "Manipulator"; }

  QString description() const override { return "Manipulator"; }

};

} // namespace Avogadro::QtPlugins

#include "ManipulatorPlugin.moc"
