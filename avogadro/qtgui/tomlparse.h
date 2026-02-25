/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_TOMLPARSE_H
#define AVOGADRO_QTGUI_TOMLPARSE_H

#include "avogadroqtguiexport.h"

#include <QtCore/QJsonObject>
#include <QtCore/QVariantMap>

#include <string_view>

class QByteArray;
class QString;

namespace Avogadro {
namespace QtGui {

/**
 * @brief Parse a TOML document and return the top-level table as a
 * QVariantMap.
 *
 * TOML types are mapped to Qt types as follows:
 *   string   → QString
 *   integer  → qlonglong
 *   float    → double
 *   boolean  → bool
 *   date     → QDate
 *   time     → QTime
 *   datetime → QDateTime
 *   array    → QVariantList
 *   table    → QVariantMap
 *
 * @param content UTF-8 encoded TOML text.
 * @param ok      If non-null, set to true on success and false on error.
 * @return The top-level TOML table as a QVariantMap; empty on parse error.
 */
AVOGADROQTGUI_EXPORT QVariantMap parseTomlString(std::string_view content,
                                                 bool* ok = nullptr);

/**
 * Overload accepting a QString (converted to UTF-8 internally).
 */
AVOGADROQTGUI_EXPORT QVariantMap parseTomlString(const QString& content,
                                                 bool* ok = nullptr);

/**
 * @brief Parse TOML bytes and return the top-level table as a QJsonObject.
 *
 * Convenience wrapper around parseTomlString() that converts the resulting
 * QVariantMap to a QJsonObject via QJsonObject::fromVariantMap().  Useful
 * when the caller needs to work with Qt's JSON types directly.
 *
 * @param content Raw UTF-8 encoded TOML bytes.
 * @param ok      If non-null, set to true on success and false on error.
 * @return The top-level TOML table as a QJsonObject; empty on parse error.
 */
AVOGADROQTGUI_EXPORT QJsonObject parseTomlToJson(const QByteArray& content,
                                                 bool* ok = nullptr);

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_TOMLPARSE_H
