/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/plotpdf/plotpdf.h"


namespace Avogadro::QtPlugins {

class PlotPdfFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit PlotPdfFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new PlotPdf(parent_);
    object->setObjectName("PlotPdf");
    return object;
  }

  QString identifier() const override { return "PlotPdf"; }

  QString description() const override { return "Create a pair distribution plot."; }

};

} // namespace Avogadro::QtPlugins

#include "PlotPdfPlugin.moc"
