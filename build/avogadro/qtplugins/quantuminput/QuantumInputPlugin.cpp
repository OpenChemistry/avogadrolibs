/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/quantuminput/quantuminput.h"


namespace Avogadro::QtPlugins {

class QuantumInputFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit QuantumInputFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new QuantumInput(parent_);
    object->setObjectName("QuantumInput");
    return object;
  }

  QString identifier() const override { return "QuantumInput"; }

  QString description() const override { return "Quantum input file generation"; }

};

} // namespace Avogadro::QtPlugins

#include "QuantumInputPlugin.moc"
