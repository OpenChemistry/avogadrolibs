/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/plotxrd/plotxrd.h"


namespace Avogadro::QtPlugins {

class PlotXrdFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit PlotXrdFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new PlotXrd(parent_);
    object->setObjectName("PlotXrd");
    return object;
  }

  QString identifier() const override { return "PlotXrd"; }

  QString description() const override { return "Use ObjCryst++ to create an XRD plot."; }

};

} // namespace Avogadro::QtPlugins

#include "PlotXrdPlugin.moc"
