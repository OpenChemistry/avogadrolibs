/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/selectiontool/selectiontool.h"


namespace Avogadro::QtPlugins {

class SelectionFactory : public QObject, public QtGui::ToolPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ToolPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ToolPluginFactory)

public:
  explicit SelectionFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ToolPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new SelectionTool(parent_);
    object->setObjectName("Selection");
    return object;
  }

  QString identifier() const override { return "Selection"; }

  QString description() const override { return "Selection tool"; }

};

} // namespace Avogadro::QtPlugins

#include "SelectionPlugin.moc"
