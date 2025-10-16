/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/spectra/spectra.h"


namespace Avogadro::QtPlugins {

class SpectraFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit SpectraFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Spectra(parent_);
    object->setObjectName("Spectra");
    return object;
  }

  QString identifier() const override { return "Spectra"; }

  QString description() const override { return "Spectra Plots"; }

};

} // namespace Avogadro::QtPlugins

#include "SpectraPlugin.moc"
