/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/qtgui/elementtranslator.h>

using Avogadro::QtGui::ElementTranslator;

TEST(ElementTranslatorTest, hydrogen)
{
  QString name = ElementTranslator::name(1);
  EXPECT_FALSE(name.isEmpty());
  EXPECT_EQ(name, QString("Hydrogen"));
}

TEST(ElementTranslatorTest, carbon)
{
  QString name = ElementTranslator::name(6);
  EXPECT_FALSE(name.isEmpty());
  EXPECT_EQ(name, QString("Carbon"));
}

TEST(ElementTranslatorTest, lastKnownElement)
{
  // Oganesson is element 118
  QString name = ElementTranslator::name(118);
  EXPECT_FALSE(name.isEmpty());
}

TEST(ElementTranslatorTest, numberOfElements)
{
  int count = ElementTranslator::numberOfElements();
  EXPECT_GE(count, 118);
}

TEST(ElementTranslatorTest, invalidZero)
{
  // Element 0 is "Dummy" or similar - should not crash
  QString name = ElementTranslator::name(0);
  // Just verify it doesn't crash; the value may be empty or "Unknown"
}

TEST(ElementTranslatorTest, beyondMax)
{
  int max = ElementTranslator::numberOfElements();
  // Should not crash for out-of-range
  QString name = ElementTranslator::name(max + 10);
}
