/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>

#include <avogadro/qtgui/jsonwidget.h>

using namespace Avogadro::QtGui;

namespace {

constexpr size_t kMaxJsonLen = 8192;

QCoreApplication* ensureApp()
{
  static int argc = 1;
  static char arg0[] = "fuzz";
  static char* argv[] = { arg0, nullptr };
  static QCoreApplication app(argc, argv);
  return &app;
}

/// Thin subclass to access protected members for fuzzing.
class FuzzableJsonWidget : public JsonWidget
{
public:
  explicit FuzzableJsonWidget(QWidget* parent = nullptr) : JsonWidget(parent) {}

  void setOptions(const QJsonObject& opts) { m_options = opts; }

  void fuzzUpdateOptions() { updateOptions(); }
};

} // namespace

// Fuzz JsonWidget by feeding random JSON as option specifications.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  ensureApp();

  // Cap input size
  if (Size > kMaxJsonLen)
    Size = kMaxJsonLen;

  // Try to parse as JSON
  QJsonParseError error;
  QByteArray raw(reinterpret_cast<const char*>(Data), static_cast<int>(Size));
  QJsonDocument doc = QJsonDocument::fromJson(raw, &error);

  if (error.error != QJsonParseError::NoError || !doc.isObject())
    return 0;

  QJsonObject obj = doc.object();

  FuzzableJsonWidget widget;
  widget.setOptions(obj);
  widget.fuzzUpdateOptions();

  // Exercise the collect → apply round-trip
  QJsonObject collected = widget.collectOptions();
  widget.applyOptions(collected);

  return 0;
}
