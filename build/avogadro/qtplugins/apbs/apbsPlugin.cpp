/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/apbs/apbs.h"


namespace Avogadro::QtPlugins {

class apbsFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit apbsFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Apbs(parent_);
    object->setObjectName("apbs");
    return object;
  }

  QString identifier() const override { return "apbs"; }

  QString description() const override { return "APBS Extension"; }

};

} // namespace Avogadro::QtPlugins

#include "apbsPlugin.moc"
