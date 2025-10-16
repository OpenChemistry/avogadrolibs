/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/bondcentrictool/bondcentrictool.h"


namespace Avogadro::QtPlugins {

class BondCentricFactory : public QObject, public QtGui::ToolPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ToolPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ToolPluginFactory)

public:
  explicit BondCentricFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ToolPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new BondCentricTool(parent_);
    object->setObjectName("BondCentric");
    return object;
  }

  QString identifier() const override { return "BondCentric"; }

  QString description() const override { return "Bond-centric"; }

};

} // namespace Avogadro::QtPlugins

#include "BondCentricPlugin.moc"
