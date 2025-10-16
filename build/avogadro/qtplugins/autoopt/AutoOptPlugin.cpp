/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/autoopt/autoopt.h"


namespace Avogadro::QtPlugins {

class AutoOptFactory : public QObject, public QtGui::ToolPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ToolPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ToolPluginFactory)

public:
  explicit AutoOptFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ToolPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new AutoOpt(parent_);
    object->setObjectName("AutoOpt");
    return object;
  }

  QString identifier() const override { return "AutoOpt"; }

  QString description() const override { return "AutoOpt"; }

};

} // namespace Avogadro::QtPlugins

#include "AutoOptPlugin.moc"
