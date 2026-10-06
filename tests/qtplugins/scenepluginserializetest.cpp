/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Settings round trip for the scene plugins that save per-layer state.
//
// Each of these plugins keeps a Core::LayerData subclass in an anonymous
// namespace, so the subclasses are not nameable here. They are reached the
// way the application reaches them: the molecule's layer info holds a plain
// LayerData carrying only the saved text (as CjsonFormat or QSettings
// restore it), and the plugin's process() calls PluginLayerManager::load<T>(),
// which rebuilds a T from that text through T::deserialize(). The result is
// read back with LayerData::serialize(), which is virtual.

#include "ballandstick.h"
#include "cartoons.h"
#include "label.h"
#include "licorice.h"
#include "vanderwaals.h"
#include "wireframe.h"

#include <avogadro/core/layermanager.h>
#include <avogadro/core/moleculeinfo.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/sceneplugin.h>
#include <avogadro/rendering/groupnode.h>

#include <QtGui/QColor>
#include <QtCore/QSettings>
#include <QtCore/QTemporaryDir>

#include <gtest/gtest.h>

#include <cmath>
#include <cstdlib>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

using namespace Avogadro;
using Avogadro::QtPlugins::BallAndStick;
using Avogadro::QtPlugins::Cartoons;
using Avogadro::QtPlugins::Label;
using Avogadro::QtPlugins::Licorice;
using Avogadro::QtPlugins::VanDerWaals;
using Avogadro::QtPlugins::Wireframe;

namespace {

// LayerManager::setActiveMolecule() is protected; this is how the plugins'
// own PluginLayerManager reaches it.
struct ActiveMolecule : Core::LayerManager
{
  static void set(const Core::Molecule* molecule)
  {
    setActiveMolecule(molecule);
  }
};

using Tokens = std::vector<std::string>;

Tokens split(const std::string& text)
{
  Tokens tokens;
  std::istringstream stream(text);
  std::string token;
  while (stream >> token)
    tokens.push_back(token);
  return tokens;
}

std::string join(const Tokens& tokens)
{
  std::string result;
  for (const auto& token : tokens) {
    if (!result.empty())
      result += ' ';
    result += token;
  }
  return result;
}

bool isBool(const std::string& token)
{
  return token == "true" || token == "false";
}

// A finite float within [low, high].
bool isFloatIn(const std::string& token, double low, double high)
{
  char* end = nullptr;
  const double value = std::strtod(token.c_str(), &end);
  if (end == token.c_str() || *end != '\0' || !std::isfinite(value))
    return false;
  return value >= low && value <= high;
}

bool isIntIn(const std::string& token, long low, long high)
{
  char* end = nullptr;
  const long value = std::strtol(token.c_str(), &end, 10);
  if (end == token.c_str() || *end != '\0')
    return false;
  return value >= low && value <= high;
}

// What one plugin contributes to the tests. Every number below is read from
// the plugin source: the defaults from the LayerData members and the QSettings
// fallbacks, the ranges from the setup widget's slider and spin box limits.
struct Spec
{
  const char* label;
  // The key the plugin stores its layer settings under (its m_name).
  const char* key;
  std::function<std::unique_ptr<QtGui::ScenePlugin>()> create;
  // Drive the plugin's own setters to non-default values.
  std::function<void(QtGui::ScenePlugin&)> applySetters;
  // serialize() of a default-constructed layer, and of the setters above.
  std::string defaults;
  std::string nonDefault;
  // True when the serialized text is well formed and every field is in range.
  std::function<bool(const Tokens&)> sane;
};

std::vector<Spec> buildSpecs()
{
  std::vector<Spec> specs;

  // multiBonds showHydrogens atomScale bondRadius opacity. The sliders are
  // 1-9 (atom), 1-8 (bond) and 0-100 (opacity), all divided to 0.1 steps.
  specs.push_back({ "BallAndStick", "Ball and Stick",
                    [] { return std::make_unique<BallAndStick>(); },
                    [](QtGui::ScenePlugin& plugin) {
                      auto& p = static_cast<BallAndStick&>(plugin);
                      p.atomRadiusChanged(5);
                      p.bondRadiusChanged(2);
                      p.opacityChanged(40);
                      p.multiBonds(false);
                      p.showHydrogens(false);
                    },
                    "true true 0.3 0.1 1", "false false 0.5 0.2 0.4",
                    [](const Tokens& t) {
                      return t.size() == 5 && isBool(t[0]) && isBool(t[1]) &&
                             isFloatIn(t[2], 0.1, 0.9) &&
                             isFloatIn(t[3], 0.1, 0.8) &&
                             isFloatIn(t[4], 0.0, 1.0);
                    } });

  // backbone trace tube ribbon simpleCartoon cartoon rope. Only "cartoon" is
  // on by default (the QSettings fallback in LayerCartoon()).
  specs.push_back({ "Cartoons", "Cartoons",
                    [] { return std::make_unique<Cartoons>(); },
                    [](QtGui::ScenePlugin& plugin) {
                      auto& p = static_cast<Cartoons&>(plugin);
                      p.showBackbone(true);
                      p.showCartoon(false);
                      p.showRope(true);
                    },
                    "false false false false false true false",
                    "true false false false false false true",
                    [](const Tokens& t) {
                      if (t.size() != 7)
                        return false;
                      for (const auto& token : t)
                        if (!isBool(token))
                          return false;
                      return true;
                    } });

  // atomOptions residueOptions radiusScalar r g b bondOptions labelScale.
  // The atom combo's index 2 is "Unique ID" (16), the residue combo's index 3
  // "Name & ID" (3) and the bond combo's index 1 "Length" (64). The distance
  // spin box is 0-1.5 and the scale spin box 0.25-3.
  specs.push_back({ "Label", "Labels", [] { return std::make_unique<Label>(); },
                    [](QtGui::ScenePlugin& plugin) {
                      auto& p = static_cast<Label&>(plugin);
                      p.atomLabelType(2);
                      p.residueLabelType(3);
                      p.bondLabelType(1);
                      p.setRadiusScalar(1.0);
                      p.setLabelScale(2.0);
                      p.setColor(QColor(10, 20, 30));
                    },
                    "2 0 0.5 255 255 255 0 1", "16 3 1 10 20 30 64 2",
                    [](const Tokens& t) {
                      return t.size() == 8 && isIntIn(t[0], 0, 0xFFFF) &&
                             isIntIn(t[1], 0, 0xFFFF) &&
                             isFloatIn(t[2], 0.0, 1.5) &&
                             isIntIn(t[3], 0, 255) && isIntIn(t[4], 0, 255) &&
                             isIntIn(t[5], 0, 255) &&
                             isIntIn(t[6], 0, 0xFFFF) &&
                             isFloatIn(t[7], 0.25, 3.0);
                    } });

  // opacity, a 0-100 slider.
  specs.push_back({ "Licorice", "Licorice",
                    [] { return std::make_unique<Licorice>(); },
                    [](QtGui::ScenePlugin& plugin) {
                      static_cast<Licorice&>(plugin).setOpacity(40);
                    },
                    "1", "0.4",
                    [](const Tokens& t) {
                      return t.size() == 1 && isFloatIn(t[0], 0.0, 1.0);
                    } });

  specs.push_back({ "VanDerWaals", "Van der Waals",
                    [] { return std::make_unique<VanDerWaals>(); },
                    [](QtGui::ScenePlugin& plugin) {
                      static_cast<VanDerWaals&>(plugin).setOpacity(40);
                    },
                    "1", "0.4",
                    [](const Tokens& t) {
                      return t.size() == 1 && isFloatIn(t[0], 0.0, 1.0);
                    } });

  // multiBonds showHydrogens lineWidth. The line width spin box is 0.5-5.
  specs.push_back({ "Wireframe", "Wireframe",
                    [] { return std::make_unique<Wireframe>(); },
                    [](QtGui::ScenePlugin& plugin) {
                      auto& p = static_cast<Wireframe&>(plugin);
                      p.multiBonds(false);
                      p.showHydrogens(false);
                      p.setWidth(2.5);
                    },
                    "true true 1", "false false 2.5",
                    [](const Tokens& t) {
                      return t.size() == 3 && isBool(t[0]) && isBool(t[1]) &&
                             isFloatIn(t[2], 0.5, 5.0);
                    } });

  return specs;
}

const std::vector<Spec>& specs()
{
  static const std::vector<Spec> s = buildSpecs();
  return s;
}

class ScenePluginSerializeTest : public ::testing::TestWithParam<size_t>
{
protected:
  void SetUp() override
  {
    // The default-constructed layer data reads QSettings, and the plugin
    // setters write it. Point both at an empty scratch file so the test
    // neither sees nor changes the user's real preferences.
    ASSERT_TRUE(m_settingsDir.isValid());
    m_oldFormat = QSettings::defaultFormat();
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope,
                       m_settingsDir.path());
    QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope,
                       m_settingsDir.path());
    QSettings().clear();
  }

  void TearDown() override
  {
    ActiveMolecule::set(nullptr);
    QSettings::setDefaultFormat(m_oldFormat);
  }

  const Spec& spec() const { return specs()[GetParam()]; }

  // The saved text of layer 0 after the plugin has done whatever
  // @p prepare asks of it; "" if there are no settings for the plugin.
  std::string runPlugin(
    const std::function<void(QtGui::Molecule&, QtGui::ScenePlugin&)>& prepare)
  {
    QtGui::Molecule molecule;
    auto plugin = spec().create();
    ActiveMolecule::set(&molecule);
    prepare(molecule, *plugin);
    auto info = molecule.layerInfo();
    auto it = info->settings.find(spec().key);
    if (it == info->settings.end() || it->second.empty() || !it->second[0]) {
      ADD_FAILURE() << "no layer settings under key " << spec().key;
      return "";
    }
    return it->second[0]->serialize();
  }

  // Restore @p saved the way a file or QSettings does -- as a plain LayerData
  // that only remembers the text -- then let process() rebuild the real type.
  std::string restore(const std::string& saved)
  {
    return runPlugin([&](QtGui::Molecule& molecule, QtGui::ScenePlugin& p) {
      auto info = molecule.layerInfo();
      info->settings[spec().key].push_back(
        std::make_shared<Core::LayerData>(saved));
      Rendering::GroupNode node;
      p.process(molecule, node);
    });
  }

  // Layer data the plugin built itself, then changed through its setters.
  std::string setWithSetters()
  {
    return runPlugin(
      [&](QtGui::Molecule&, QtGui::ScenePlugin& p) { spec().applySetters(p); });
  }

  QTemporaryDir m_settingsDir;
  QSettings::Format m_oldFormat = QSettings::NativeFormat;
};

} // namespace

TEST_P(ScenePluginSerializeTest, defaultsMatchTheSource)
{
  // Nothing saved: the layer data comes from the QSettings fallbacks.
  EXPECT_EQ(restore(""), spec().defaults);
}

TEST_P(ScenePluginSerializeTest, defaultRoundTrip)
{
  const std::string first = restore(spec().defaults);
  EXPECT_EQ(first, spec().defaults);
  EXPECT_EQ(restore(first), first);
}

TEST_P(ScenePluginSerializeTest, settersRoundTrip)
{
  const std::string saved = setWithSetters();
  EXPECT_EQ(saved, spec().nonDefault);
  EXPECT_NE(saved, spec().defaults);

  // A fresh instance, a fresh molecule, only the text carried over.
  EXPECT_EQ(restore(saved), saved);
}

TEST_P(ScenePluginSerializeTest, deserializeThenSerializeIsStable)
{
  const std::string s = spec().nonDefault;
  EXPECT_EQ(restore(s), s);
}

TEST_P(ScenePluginSerializeTest, cloneKeepsTheSettings)
{
  QtGui::Molecule molecule;
  auto plugin = spec().create();
  ActiveMolecule::set(&molecule);
  spec().applySetters(*plugin);
  auto info = molecule.layerInfo();
  auto& data = info->settings[spec().key];
  ASSERT_FALSE(data.empty());
  std::unique_ptr<Core::LayerData> copy(data[0]->clone());
  ASSERT_TRUE(copy != nullptr);
  EXPECT_EQ(copy->serialize(), spec().nonDefault);
}

TEST_P(ScenePluginSerializeTest, whitespaceAndNewlinesAreSeparators)
{
  const Tokens fields = split(spec().nonDefault);
  std::string text = "  \t";
  for (const auto& field : fields)
    text += field + "\n";
  EXPECT_EQ(restore(text), spec().nonDefault);
}

TEST_P(ScenePluginSerializeTest, emptyAndBlankInputKeepDefaults)
{
  EXPECT_EQ(restore(""), spec().defaults);
  EXPECT_EQ(restore("   "), spec().defaults);
  EXPECT_EQ(restore(" \t\r\n "), spec().defaults);
}

TEST_P(ScenePluginSerializeTest, truncatedInputKeepsTheMissingFieldsDefault)
{
  const Tokens given = split(spec().nonDefault);
  const Tokens dflt = split(spec().defaults);
  ASSERT_EQ(given.size(), dflt.size());

  for (size_t keep = 0; keep < given.size(); ++keep) {
    Tokens prefix(given.begin(), given.begin() + keep);
    Tokens expected = prefix;
    expected.insert(expected.end(), dflt.begin() + keep, dflt.end());
    EXPECT_EQ(restore(join(prefix)), join(expected))
      << "kept " << keep << " fields of \"" << spec().nonDefault << "\"";
  }
}

TEST_P(ScenePluginSerializeTest, extraFieldsAreIgnored)
{
  EXPECT_EQ(restore(spec().nonDefault + " 1 2 3 extra"), spec().nonDefault);
  EXPECT_EQ(restore(spec().nonDefault + " true -7 nan"), spec().nonDefault);
}

TEST_P(ScenePluginSerializeTest, badFieldsLeaveSaneData)
{
  const std::vector<std::string> bad = {
    "abc",
    "true1",
    "99999999999999999999",
    "-99999999999999999999",
    "1e30",
    "-1e30",
    "-1",
    "-0.5",
    "0",
    "nan",
    "NaN",
    "inf",
    "-inf",
    "Infinity",
    "0x10",
    "1.5.5",
    ".",
    "-",
    "+",
    "1e",
  };

  const Tokens given = split(spec().nonDefault);
  for (size_t field = 0; field < given.size(); ++field) {
    for (const auto& token : bad) {
      Tokens text = given;
      text[field] = token;
      const std::string input = join(text);
      const std::string out = restore(input);
      EXPECT_TRUE(spec().sane(split(out)))
        << "input \"" << input << "\" gave \"" << out << "\"";
    }
  }
}

TEST_P(ScenePluginSerializeTest, embeddedNulAndNewlineLeaveSaneData)
{
  const std::string good = spec().nonDefault;
  std::vector<std::string> inputs;
  // A NUL at every position, in place of the character there, and inserted.
  for (size_t i = 0; i <= good.size(); ++i) {
    std::string inserted = good;
    inserted.insert(i, 1, '\0');
    inputs.push_back(inserted);
    if (i < good.size()) {
      std::string replaced = good;
      replaced[i] = '\0';
      inputs.push_back(replaced);
    }
  }
  inputs.push_back(std::string("\0", 1));
  inputs.push_back(std::string("\0\0\0", 3));
  inputs.push_back("\n");
  inputs.push_back("\n\n" + good + "\n\n");
  inputs.push_back(std::string("\n\0\n", 3));

  for (const auto& input : inputs) {
    const std::string out = restore(input);
    EXPECT_TRUE(spec().sane(split(out)))
      << "input of " << input.size() << " bytes gave \"" << out << "\"";
  }
}

TEST_P(ScenePluginSerializeTest, nothingSavedForOtherPluginsIsTouched)
{
  // A plugin only rebuilds the layer data stored under its own key.
  QtGui::Molecule molecule;
  auto plugin = spec().create();
  ActiveMolecule::set(&molecule);
  auto info = molecule.layerInfo();
  info->settings["Some other plugin"].push_back(
    std::make_shared<Core::LayerData>("untouched"));
  Rendering::GroupNode node;
  plugin->process(molecule, node);
  EXPECT_EQ(info->settings["Some other plugin"][0]->getSave(), "untouched");
}

INSTANTIATE_TEST_SUITE_P(ScenePlugins, ScenePluginSerializeTest,
                         ::testing::Range<size_t>(0, 6),
                         [](const ::testing::TestParamInfo<size_t>& info) {
                           return std::string(specs()[info.param].label);
                         });
