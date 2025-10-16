/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/plotrmsd/plotrmsd.h"


namespace Avogadro::QtPlugins {

class PlotRmsdFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit PlotRmsdFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new PlotRmsd(parent_);
    object->setObjectName("PlotRmsd");
    return object;
  }

  QString identifier() const override { return "PlotRmsd"; }

  QString description() const override { return "Create an RMSD plot."; }

};

} // namespace Avogadro::QtPlugins

#include "PlotRmsdPlugin.moc"
