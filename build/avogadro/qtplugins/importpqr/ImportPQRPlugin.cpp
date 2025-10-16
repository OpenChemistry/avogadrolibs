/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/importpqr/importpqr.h"


namespace Avogadro::QtPlugins {

class ImportPQRFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit ImportPQRFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new ImportPQR(parent_);
    object->setObjectName("ImportPQR");
    return object;
  }

  QString identifier() const override { return "ImportPQR"; }

  QString description() const override { return "Download molecules from the Pitt Quantum Repository"; }

};

} // namespace Avogadro::QtPlugins

#include "ImportPQRPlugin.moc"
