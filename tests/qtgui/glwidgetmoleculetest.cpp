/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtopengl/glwidget.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QObject>
#include <QtWidgets/QApplication>

using Avogadro::QtGui::Molecule;
using Avogadro::QtOpenGL::GLWidget;

namespace {

/**
 * GLWidget is a QWidget, so a plain QCoreApplication is not enough. Other tests
 * in this binary may have created one already; if that instance is not a
 * QApplication there is no way to upgrade it, and the caller skips.
 */
QApplication* ensureApp()
{
  if (QCoreApplication::instance() != nullptr)
    return qobject_cast<QApplication*>(QCoreApplication::instance());

  static int argc = 1;
  static char arg0[] = "glwidgetmoleculetest";
  static char* argv[] = { arg0, nullptr };
  // Run without a display so this works in CI.
  if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM"))
    qputenv("QT_QPA_PLATFORM", "offscreen");
  static QApplication app(argc, argv);
  return &app;
}

} // namespace

// The widget is never shown, so no OpenGL context is created: setMolecule()
// only touches the scene graph and the signal connections.
TEST(GLWidgetMoleculeTest, setMoleculeKeepsOtherConnections)
{
  if (ensureApp() == nullptr)
    GTEST_SKIP() << "A QApplication is required for QWidget tests.";

  Molecule first;
  Molecule second;
  // An external object (standing in for the main window) watching the molecule.
  QObject observer;
  int count = 0;
  auto onChanged = [&count](unsigned int) { ++count; };
  QObject::connect(&first, &Molecule::changed, &observer, onChanged);

  GLWidget widget;
  widget.setMolecule(&first);
  EXPECT_EQ(widget.molecule(), &first);

  first.emitChanged(Molecule::Atoms);
  EXPECT_EQ(count, 1);

  // Moving the widget to another molecule must leave the observer's connection
  // to the first one alone: the main window relies on exactly this to track
  // modifications.
  widget.setMolecule(&second);
  EXPECT_EQ(widget.molecule(), &second);

  first.emitChanged(Molecule::Atoms);
  EXPECT_EQ(count, 2);

  // Same for the molecule the widget has just taken over: re-setting it must
  // not discard the observer either.
  QObject::connect(&second, &Molecule::changed, &observer, onChanged);
  widget.setMolecule(&second);
  second.emitChanged(Molecule::Atoms);
  EXPECT_EQ(count, 3);
}

TEST(GLWidgetMoleculeTest, setMoleculeNullIsSafe)
{
  if (ensureApp() == nullptr)
    GTEST_SKIP() << "A QApplication is required for QWidget tests.";

  Molecule mol;
  GLWidget widget;
  widget.setMolecule(&mol);
  widget.setMolecule(nullptr);
  EXPECT_EQ(widget.molecule(), nullptr);
  // No longer connected: this must not reach the widget (or crash).
  mol.emitChanged(Molecule::Atoms);
}
