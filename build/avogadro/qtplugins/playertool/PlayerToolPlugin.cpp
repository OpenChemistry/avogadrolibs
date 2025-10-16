/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/playertool/playertool.h"


namespace Avogadro::QtPlugins {

class PlayerToolFactory : public QObject, public QtGui::ToolPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ToolPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ToolPluginFactory)

public:
  explicit PlayerToolFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ToolPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new PlayerTool(parent_);
    object->setObjectName("PlayerTool");
    return object;
  }

  QString identifier() const override { return "PlayerTool"; }

  QString description() const override { return "Player tool"; }

};

} // namespace Avogadro::QtPlugins

#include "PlayerToolPlugin.moc"
