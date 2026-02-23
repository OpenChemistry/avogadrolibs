/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "tomlparse.h"

#include <QtCore/QDate>
#include <QtCore/QDateTime>
#include <QtCore/QDebug>
#include <QtCore/QString>
#include <QtCore/QTime>
#include <QtCore/QTimeZone>

// tomlplusplus — single header in thirdparty/
#include <toml.hpp>

namespace Avogadro::QtGui {

// ---------------------------------------------------------------------------
// Internal TOML → QVariant helpers
// ---------------------------------------------------------------------------

static QVariant tomlNodeToVariant(const toml::node& node);

static QVariantMap tomlTableToVariantMap(const toml::table& tbl)
{
  QVariantMap map;
  for (auto&& [key, val] : tbl) {
    map.insert(QString::fromStdString(std::string(key.str())),
               tomlNodeToVariant(val));
  }
  return map;
}

static QVariantList tomlArrayToVariantList(const toml::array& arr)
{
  QVariantList list;
  for (auto&& val : arr) {
    list.append(tomlNodeToVariant(val));
  }
  return list;
}

static QVariant tomlNodeToVariant(const toml::node& node)
{
  if (node.is_string())
    return QString::fromStdString(std::string(node.as_string()->get()));
  if (node.is_integer())
    return static_cast<qlonglong>(node.as_integer()->get());
  if (node.is_floating_point())
    return node.as_floating_point()->get();
  if (node.is_boolean())
    return node.as_boolean()->get();
  if (node.is_table())
    return tomlTableToVariantMap(*node.as_table());
  if (node.is_array())
    return tomlArrayToVariantList(*node.as_array());
  if (node.is_date()) {
    auto d = node.as_date()->get();
    return QDate(d.year, d.month, d.day);
  }
  if (node.is_time()) {
    auto t = node.as_time()->get();
    return QTime(t.hour, t.minute, t.second, t.nanosecond / 1000000);
  }
  if (node.is_date_time()) {
    auto dt = node.as_date_time()->get();
    QDate date(dt.date.year, dt.date.month, dt.date.day);
    QTime time(dt.time.hour, dt.time.minute, dt.time.second,
               dt.time.nanosecond / 1000000);
    if (dt.offset)
      return QDateTime(date, time, QTimeZone(dt.offset->minutes * 60));
    return QDateTime(date, time);
  }
  return {};
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

QVariantMap parseTomlString(std::string_view content, bool* ok)
{
  try {
    toml::table root = toml::parse(content);
    if (ok)
      *ok = true;
    return tomlTableToVariantMap(root);
  } catch (const toml::parse_error& err) {
    qWarning() << "TOML parse error:" << err.what();
    if (ok)
      *ok = false;
    return {};
  }
}

QVariantMap parseTomlString(const QString& content, bool* ok)
{
  QByteArray utf8 = content.toUtf8();
  return parseTomlString(std::string_view(utf8.constData(), utf8.size()), ok);
}

} // namespace Avogadro::QtGui
