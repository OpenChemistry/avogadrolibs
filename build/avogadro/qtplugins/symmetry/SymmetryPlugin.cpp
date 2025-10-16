/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/symmetry/symmetry.h"


namespace Avogadro::QtPlugins {

class SymmetryFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit SymmetryFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Symmetry(parent_);
    object->setObjectName("Symmetry");
    return object;
  }

  QString identifier() const override { return "Symmetry"; }

  QString description() const override { return "Provide symmetry functionality."; }

};

} // namespace Avogadro::QtPlugins

#include "SymmetryPlugin.moc"
