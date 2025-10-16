/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/customelements/customelements.h"


namespace Avogadro::QtPlugins {

class CustomElementsFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit CustomElementsFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new CustomElements(parent_);
    object->setObjectName("CustomElements");
    return object;
  }

  QString identifier() const override { return "CustomElements"; }

  QString description() const override { return "Manipulate custom element types in the current molecule."; }

};

} // namespace Avogadro::QtPlugins

#include "CustomElementsPlugin.moc"
