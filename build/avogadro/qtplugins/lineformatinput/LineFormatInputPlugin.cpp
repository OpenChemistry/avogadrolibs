/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/lineformatinput/lineformatinput.h"


namespace Avogadro::QtPlugins {

class LineFormatInputFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit LineFormatInputFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new LineFormatInput(parent_);
    object->setObjectName("LineFormatInput");
    return object;
  }

  QString identifier() const override { return "LineFormatInput"; }

  QString description() const override { return "Enter line formats in a dialog window."; }

};

} // namespace Avogadro::QtPlugins

#include "LineFormatInputPlugin.moc"
