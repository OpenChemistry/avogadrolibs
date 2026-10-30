/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandregistry.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>

#include <QtCore/QDebug>
#include <QtCore/QJsonArray>
#include <QtCore/QMetaType>
#include <QtCore/QSet>
#include <QtGui/QColor>

#include <algorithm>
#include <cmath>
#include <limits>
#include <utility>

namespace Avogadro {
namespace QtGui {

namespace {

/// Whether @p value holds an actual JSON number, as opposed to some other
/// type that QVariant would still convert on request -- a QString "3" or a
/// bool, say. These must be rejected rather than silently coerced.
bool isNumericVariant(const QVariant& value)
{
  switch (value.typeId()) {
    case QMetaType::Double:
    case QMetaType::Float:
    case QMetaType::Int:
    case QMetaType::UInt:
    case QMetaType::Long:
    case QMetaType::ULong:
    case QMetaType::LongLong:
    case QMetaType::ULongLong:
    case QMetaType::Short:
    case QMetaType::UShort:
      return true;
    default:
      return false;
  }
}

/// Whether @p value is a number holding a whole value (not NaN); the value is
/// returned in @p out.
bool wholeNumber(const QVariant& value, double& out)
{
  if (!isNumericVariant(value))
    return false;
  out = value.toDouble();
  return !std::isnan(out) && std::floor(out) == out;
}

QString formatNumber(double value)
{
  return QString::number(value, 'g', 15);
}

QString noMoleculeMessage()
{
  return CommandRegistry::tr("No molecule");
}

/// Check one index. @p position is the 1-based place in a list, or 0 for a
/// stand-alone atom index.
bool parseOneIndex(const QVariant& value, int position, const QString& name,
                   Index atomCount, Index& out, QString& error)
{
  const auto notWhole = [&]() {
    error =
      position > 0
        ? CommandRegistry::tr("atom index #%1 in %2 must be a whole number.")
            .arg(position)
            .arg(name)
        : CommandRegistry::tr("%1 must be a whole number (an atom "
                              "index).")
            .arg(name);
  };

  double raw = 0.0;
  if (!wholeNumber(value, raw)) {
    notWhole();
    return false;
  }
  if (raw < 0.0) {
    error = position > 0
              ? CommandRegistry::tr("atom index #%1 in %2 is negative; atom "
                                    "indices must be zero or greater.")
                  .arg(position)
                  .arg(name)
              : CommandRegistry::tr("%1 is negative; atom indices must be zero "
                                    "or greater.")
                  .arg(name);
    return false;
  }
  // Comparing as doubles, before casting, keeps an absurdly large index
  // from overflowing Index rather than simply failing this check.
  if (!(raw < static_cast<double>(atomCount))) {
    // %n lets each language supply its own plural forms for "atoms".
    error = CommandRegistry::tr("atom index %1 is out of range (the molecule "
                                "has %n atom(s)).",
                                nullptr, static_cast<int>(atomCount))
              .arg(raw, 0, 'f', 0);
    return false;
  }

  out = static_cast<Index>(raw);
  return true;
}

/// Whether @p key is the name or an alias of one of @p command's options.
bool isKnownOption(const CommandSpec& command, const QString& key)
{
  for (const auto& argument : command.arguments) {
    if (argument.name == key || argument.aliases.contains(key))
      return true;
  }
  return false;
}

bool countAcceptable(const CommandArgumentSpec& spec, size_t count)
{
  if (count < static_cast<size_t>(std::max(spec.minCount, 0)))
    return false;
  if (spec.maxCount >= 0 && count > static_cast<size_t>(spec.maxCount))
    return false;
  return true;
}

QString countMessage(const CommandArgumentSpec& spec)
{
  if (spec.maxCount >= 0 && spec.minCount == spec.maxCount) {
    return CommandRegistry::tr("%1 must list exactly %n atom index(es).",
                               nullptr, spec.maxCount)
      .arg(spec.name);
  }
  if (spec.maxCount < 0) {
    return CommandRegistry::tr("%1 must list at least %n atom index(es).",
                               nullptr, spec.minCount)
      .arg(spec.name);
  }
  if (spec.minCount <= 0) {
    return CommandRegistry::tr("%1 must list at most %n atom index(es).",
                               nullptr, spec.maxCount)
      .arg(spec.name);
  }
  return CommandRegistry::tr("%1 must list between %2 and %3 atom indices.")
    .arg(spec.name)
    .arg(spec.minCount)
    .arg(spec.maxCount);
}

/// @p value with @p unit appended: directly for angle symbols, with a space
/// otherwise (the SI convention).
QString formatQuantity(double value, const QString& unit)
{
  const QString number = formatNumber(value);
  if (unit.isEmpty())
    return number;
  const bool tight = unit == QStringLiteral("°") ||
                     unit == QStringLiteral("′") || unit == QStringLiteral("″");
  return tight ? number + unit : number + QLatin1Char(' ') + unit;
}

bool checkRange(const CommandArgumentSpec& spec, double number, QString& error)
{
  if (spec.minimum && number < *spec.minimum) {
    error = CommandRegistry::tr("%1 must be at least %2.")
              .arg(spec.name)
              .arg(formatQuantity(*spec.minimum, spec.unit));
    return false;
  }
  if (spec.maximum && number > *spec.maximum) {
    error = CommandRegistry::tr("%1 must be at most %2.")
              .arg(spec.name)
              .arg(formatQuantity(*spec.maximum, spec.unit));
    return false;
  }
  return true;
}

bool parseInteger(const QVariant& value, const CommandArgumentSpec& spec,
                  qlonglong& out, QString& error)
{
  const auto notWhole = [&]() {
    error = CommandRegistry::tr("%1 must be a whole number.").arg(spec.name);
    return false;
  };
  if (!isNumericVariant(value))
    return notWhole();

  qlonglong result = 0;
  switch (value.typeId()) {
    case QMetaType::Double:
    case QMetaType::Float: {
      double raw = 0.0;
      // 2^63 is exactly representable; anything at or past it won't fit.
      constexpr double limit = 9223372036854775808.0;
      if (!wholeNumber(value, raw))
        return notWhole();
      if (!(raw >= -limit && raw < limit)) {
        error = CommandRegistry::tr("%1 is too large.").arg(spec.name);
        return false;
      }
      result = static_cast<qlonglong>(raw);
      break;
    }
    case QMetaType::ULongLong:
    case QMetaType::ULong: {
      const qulonglong raw = value.toULongLong();
      if (raw >
          static_cast<qulonglong>(std::numeric_limits<qlonglong>::max())) {
        error = CommandRegistry::tr("%1 is too large.").arg(spec.name);
        return false;
      }
      result = static_cast<qlonglong>(raw);
      break;
    }
    default:
      result = value.toLongLong();
      break;
  }

  if (!checkRange(spec, static_cast<double>(result), error))
    return false;
  out = result;
  return true;
}

bool parseReal(const QVariant& value, const CommandArgumentSpec& spec,
               double& out, QString& error)
{
  if (!isNumericVariant(value) || !std::isfinite(value.toDouble())) {
    error = CommandRegistry::tr("%1 must be a finite number.").arg(spec.name);
    return false;
  }
  const double raw = value.toDouble();
  if (!checkRange(spec, raw, error))
    return false;
  out = raw;
  return true;
}

/// Three finite numbers, as a JSON [x, y, z] arrives.
bool parseVector3(const QVariant& value, const CommandArgumentSpec& spec,
                  QVariantList& out, QString& error)
{
  bool valid = value.typeId() == QMetaType::QVariantList;
  QVariantList components;
  if (valid) {
    components = value.toList();
    valid = components.size() == 3;
  }
  for (qsizetype i = 0; valid && i < components.size(); ++i) {
    valid = isNumericVariant(components[i]) &&
            std::isfinite(components[i].toDouble());
  }
  if (!valid) {
    // The unit is inside the message so that translators can place it.
    error = spec.unit.isEmpty()
              ? CommandRegistry::tr("%1 must be a list of 3 finite numbers "
                                    "[x, y, z].")
                  .arg(spec.name)
              : CommandRegistry::tr("%1 must be a list of 3 finite numbers "
                                    "[x, y, z] in %2.")
                  .arg(spec.name)
                  .arg(spec.unit);
    return false;
  }
  out.clear();
  for (const QVariant& component : components)
    out << component.toDouble();
  return true;
}

QString colorMessage(const CommandArgumentSpec& spec)
{
  return spec.allowAlpha
           ? CommandRegistry::tr("%1 must be a color: \"#RRGGBB\", a color "
                                 "name, or [r, g, b, a] with values 0-255.")
               .arg(spec.name)
           : CommandRegistry::tr("%1 must be a color: \"#RRGGBB\", a color "
                                 "name, or [r, g, b] with values 0-255.")
               .arg(spec.name);
}

/// Parse "#RGB", "#RRGGBB" and, with alpha, "#RGBA" / "#RRGGBBAA".
///
/// This is done by hand rather than with QColor(QString), because Qt reads
/// an 8-digit string as #AARRGGBB while CSS, and so most scripts and web
/// tools, put the alpha last (#RRGGBBAA). We follow CSS.
bool parseHexColor(const QString& text, const CommandArgumentSpec& spec,
                   QColor& out, QString& error)
{
  const QString digits = text.mid(1);
  bool hex = !digits.isEmpty();
  for (const QChar c : digits) {
    const QChar lower = c.toLower();
    hex = hex && ((c >= QLatin1Char('0') && c <= QLatin1Char('9')) ||
                  (lower >= QLatin1Char('a') && lower <= QLatin1Char('f')));
  }
  const qsizetype n = digits.size();
  if (!hex || (n != 3 && n != 4 && n != 6 && n != 8)) {
    error = colorMessage(spec);
    return false;
  }
  if ((n == 4 || n == 8) && !spec.allowAlpha) {
    error = CommandRegistry::tr("%1 does not take an alpha channel; give "
                                "\"#RRGGBB\" or [r, g, b].")
              .arg(spec.name);
    return false;
  }

  const int step = (n == 3 || n == 4) ? 1 : 2;
  int channel[4] = { 0, 0, 0, 255 };
  for (int i = 0; i * step < n; ++i) {
    const QString part = digits.mid(i * step, step);
    // "#f08" means "#ff0088": a single digit is doubled.
    channel[i] = (step == 1 ? part + part : part).toInt(nullptr, 16);
  }
  out = QColor(channel[0], channel[1], channel[2], channel[3]);
  return true;
}

/// Whether @p name is a color name QColor knows. QColor::isValidColorName()
/// is new in Qt 6.4; older Qt 6 releases only have isValidColor().
bool isValidColorName(const QString& name)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 4, 0)
  return QColor::isValidColorName(name);
#else
  return QColor::isValidColor(name);
#endif
}

bool parseColor(const QVariant& value, const CommandArgumentSpec& spec,
                QColor& out, QString& error)
{
  if (value.typeId() == QMetaType::QString) {
    const QString text = value.toString().trimmed();
    if (text.startsWith(QLatin1Char('#')))
      return parseHexColor(text, spec, out, error);
    // QColor is used only to look up names, which are all alpha 255 except
    // "transparent".
    if (!text.isEmpty() && isValidColorName(text)) {
      const QColor named(text);
      if (named.alpha() == 255 || spec.allowAlpha) {
        out = named;
        return true;
      }
    }
    error = colorMessage(spec);
    return false;
  }

  if (value.typeId() == QMetaType::QVariantList) {
    const QVariantList list = value.toList();
    const qsizetype count = list.size();
    bool valid = count == 3 || (count == 4 && spec.allowAlpha);
    int channel[4] = { 0, 0, 0, 255 };
    for (qsizetype i = 0; valid && i < count; ++i) {
      double number = 0.0;
      valid = wholeNumber(list[i], number) && number >= 0.0 && number <= 255.0;
      if (valid)
        channel[i] = static_cast<int>(number);
    }
    if (valid) {
      out = QColor(channel[0], channel[1], channel[2], channel[3]);
      return true;
    }
  }

  error = colorMessage(spec);
  return false;
}

/// Convert and store one present (or defaulted) value.
bool convert(const CommandArgumentSpec& spec, const QVariant& value,
             const Core::Molecule* molecule, QVariantMap& scalars,
             std::map<QString, std::vector<Index>>& lists, QString& error)
{
  switch (spec.type) {
    case CommandArgumentType::AtomIndices: {
      if (molecule == nullptr) {
        error = noMoleculeMessage();
        return false;
      }
      std::vector<Index> indices;
      if (!CommandRegistry::parseAtomIndices(value, spec, *molecule, indices,
                                             error))
        return false;
      lists[spec.name] = std::move(indices);
      return true;
    }
    case CommandArgumentType::AtomIndex: {
      if (molecule == nullptr) {
        error = noMoleculeMessage();
        return false;
      }
      Index index = 0;
      if (!CommandRegistry::parseAtomIndex(value, spec, *molecule, index,
                                           error))
        return false;
      scalars[spec.name] = QVariant::fromValue<qulonglong>(index);
      return true;
    }
    case CommandArgumentType::Element: {
      unsigned char atomicNumber = 0;
      if (!CommandRegistry::parseElement(value, atomicNumber, error))
        return false;
      scalars[spec.name] = static_cast<uint>(atomicNumber);
      return true;
    }
    case CommandArgumentType::Integer: {
      qlonglong number = 0;
      if (!parseInteger(value, spec, number, error))
        return false;
      scalars[spec.name] = number;
      return true;
    }
    case CommandArgumentType::Real: {
      double number = 0.0;
      if (!parseReal(value, spec, number, error))
        return false;
      scalars[spec.name] = number;
      return true;
    }
    case CommandArgumentType::String: {
      if (value.typeId() != QMetaType::QString) {
        error = CommandRegistry::tr("%1 must be a string.").arg(spec.name);
        return false;
      }
      scalars[spec.name] = value.toString();
      return true;
    }
    case CommandArgumentType::Enum: {
      if (value.typeId() != QMetaType::QString ||
          !spec.allowedValues.contains(value.toString())) {
        error = CommandRegistry::tr("%1 must be one of: %2.")
                  .arg(spec.name)
                  .arg(spec.allowedValues.join(QStringLiteral(", ")));
        return false;
      }
      scalars[spec.name] = value.toString();
      return true;
    }
    case CommandArgumentType::Bool: {
      if (value.typeId() != QMetaType::Bool) {
        error = CommandRegistry::tr("%1 must be true or false.").arg(spec.name);
        return false;
      }
      scalars[spec.name] = value.toBool();
      return true;
    }
    case CommandArgumentType::Vector3: {
      QVariantList components;
      if (!parseVector3(value, spec, components, error))
        return false;
      scalars[spec.name] = components;
      return true;
    }
    case CommandArgumentType::Color: {
      QColor parsed;
      if (!parseColor(value, spec, parsed, error))
        return false;
      scalars[spec.name] = parsed;
      return true;
    }
  }
  return false;
}

QJsonObject argumentSchema(const CommandArgumentSpec& spec)
{
  QJsonObject property;
  switch (spec.type) {
    case CommandArgumentType::AtomIndices: {
      property[QStringLiteral("type")] = QStringLiteral("array");
      QJsonObject items;
      items[QStringLiteral("type")] = QStringLiteral("integer");
      items[QStringLiteral("minimum")] = 0;
      property[QStringLiteral("items")] = items;
      if (spec.minCount > 0)
        property[QStringLiteral("minItems")] = spec.minCount;
      if (spec.maxCount >= 0)
        property[QStringLiteral("maxItems")] = spec.maxCount;
      property[QStringLiteral("uniqueItems")] = spec.unique;
      if (spec.selectionFallback)
        property[QStringLiteral("x-avogadro-default")] =
          QStringLiteral("selection");
      break;
    }
    case CommandArgumentType::Element: {
      QJsonObject number;
      number[QStringLiteral("type")] = QStringLiteral("integer");
      number[QStringLiteral("minimum")] = 1;
      number[QStringLiteral("maximum")] =
        static_cast<int>(Core::Elements::elementCount()) - 1;
      QJsonObject text;
      text[QStringLiteral("type")] = QStringLiteral("string");
      property[QStringLiteral("oneOf")] = QJsonArray{ number, text };
      break;
    }
    case CommandArgumentType::Enum:
      property[QStringLiteral("type")] = QStringLiteral("string");
      property[QStringLiteral("enum")] =
        QJsonArray::fromStringList(spec.allowedValues);
      break;
    case CommandArgumentType::AtomIndex:
      property[QStringLiteral("type")] = QStringLiteral("integer");
      property[QStringLiteral("minimum")] = 0;
      break;
    case CommandArgumentType::Integer:
      property[QStringLiteral("type")] = QStringLiteral("integer");
      break;
    case CommandArgumentType::Real:
      property[QStringLiteral("type")] = QStringLiteral("number");
      break;
    case CommandArgumentType::Bool:
      property[QStringLiteral("type")] = QStringLiteral("boolean");
      break;
    case CommandArgumentType::String:
      property[QStringLiteral("type")] = QStringLiteral("string");
      break;
    case CommandArgumentType::Vector3: {
      property[QStringLiteral("type")] = QStringLiteral("array");
      QJsonObject items;
      items[QStringLiteral("type")] = QStringLiteral("number");
      property[QStringLiteral("items")] = items;
      property[QStringLiteral("minItems")] = 3;
      property[QStringLiteral("maxItems")] = 3;
      break;
    }
    case CommandArgumentType::Color: {
      QJsonObject text;
      text[QStringLiteral("type")] = QStringLiteral("string");
      text[QStringLiteral("x-avogadro-format")] = QStringLiteral("color");
      if (spec.allowAlpha)
        text[QStringLiteral("x-avogadro-hex-order")] =
          QStringLiteral("RRGGBBAA");
      QJsonObject channel;
      channel[QStringLiteral("type")] = QStringLiteral("integer");
      channel[QStringLiteral("minimum")] = 0;
      channel[QStringLiteral("maximum")] = 255;
      QJsonObject list;
      list[QStringLiteral("type")] = QStringLiteral("array");
      list[QStringLiteral("items")] = channel;
      list[QStringLiteral("minItems")] = 3;
      list[QStringLiteral("maxItems")] = spec.allowAlpha ? 4 : 3;
      property[QStringLiteral("oneOf")] = QJsonArray{ text, list };
      break;
    }
  }

  if (spec.type == CommandArgumentType::Integer ||
      spec.type == CommandArgumentType::Real) {
    if (spec.minimum)
      property[QStringLiteral("minimum")] = *spec.minimum;
    if (spec.maximum)
      property[QStringLiteral("maximum")] = *spec.maximum;
  }

  if (!spec.unit.isEmpty())
    property[QStringLiteral("x-avogadro-unit")] = spec.unit;
  if (!spec.description.isEmpty())
    property[QStringLiteral("description")] = spec.description;
  if (spec.defaultValue.isValid())
    property[QStringLiteral("default")] =
      QJsonValue::fromVariant(spec.defaultValue);
  return property;
}

} // namespace

// ---- CommandArgumentSpec -------------------------------------------------

namespace {
CommandArgumentSpec makeSpec(CommandArgumentType type, const QString& name,
                             const QString& description)
{
  CommandArgumentSpec spec;
  spec.type = type;
  spec.name = name;
  spec.description = description;
  return spec;
}
} // namespace

CommandArgumentSpec CommandArgumentSpec::atomIndices(const QString& name,
                                                     const QString& description)
{
  return makeSpec(CommandArgumentType::AtomIndices, name, description);
}

CommandArgumentSpec CommandArgumentSpec::atomIndex(const QString& name,
                                                   const QString& description)
{
  return makeSpec(CommandArgumentType::AtomIndex, name, description);
}

CommandArgumentSpec CommandArgumentSpec::element(const QString& name,
                                                 const QString& description)
{
  return makeSpec(CommandArgumentType::Element, name, description);
}

CommandArgumentSpec CommandArgumentSpec::integer(const QString& name,
                                                 const QString& description)
{
  return makeSpec(CommandArgumentType::Integer, name, description);
}

CommandArgumentSpec CommandArgumentSpec::real(const QString& name,
                                              const QString& description)
{
  return makeSpec(CommandArgumentType::Real, name, description);
}

CommandArgumentSpec CommandArgumentSpec::string(const QString& name,
                                                const QString& description)
{
  return makeSpec(CommandArgumentType::String, name, description);
}

CommandArgumentSpec CommandArgumentSpec::enumeration(
  const QString& name, const QString& description,
  const QStringList& allowedValues)
{
  CommandArgumentSpec spec =
    makeSpec(CommandArgumentType::Enum, name, description);
  spec.allowedValues = allowedValues;
  return spec;
}

CommandArgumentSpec CommandArgumentSpec::boolean(const QString& name,
                                                 const QString& description)
{
  return makeSpec(CommandArgumentType::Bool, name, description);
}

CommandArgumentSpec CommandArgumentSpec::vector3(const QString& name,
                                                 const QString& description)
{
  return makeSpec(CommandArgumentType::Vector3, name, description);
}

CommandArgumentSpec CommandArgumentSpec::color(const QString& name,
                                               const QString& description)
{
  return makeSpec(CommandArgumentType::Color, name, description);
}

CommandArgumentSpec CommandArgumentSpec::withRequired(bool isRequired) const
{
  CommandArgumentSpec copy(*this);
  copy.required = isRequired;
  return copy;
}

CommandArgumentSpec CommandArgumentSpec::withDefault(
  const QVariant& value) const
{
  CommandArgumentSpec copy(*this);
  copy.defaultValue = value;
  return copy;
}

CommandArgumentSpec CommandArgumentSpec::withAliases(
  const QStringList& aliasNames) const
{
  CommandArgumentSpec copy(*this);
  copy.aliases = aliasNames;
  return copy;
}

CommandArgumentSpec CommandArgumentSpec::withUnit(const QString& unitText) const
{
  CommandArgumentSpec copy(*this);
  copy.unit = unitText;
  return copy;
}

CommandArgumentSpec CommandArgumentSpec::withRange(
  std::optional<double> minimumValue, std::optional<double> maximumValue) const
{
  CommandArgumentSpec copy(*this);
  copy.minimum = minimumValue;
  copy.maximum = maximumValue;
  return copy;
}

CommandArgumentSpec CommandArgumentSpec::withCount(int minimumCount,
                                                   int maximumCount) const
{
  CommandArgumentSpec copy(*this);
  copy.minCount = minimumCount;
  copy.maxCount = maximumCount;
  return copy;
}

CommandArgumentSpec CommandArgumentSpec::withUnique(bool mustBeUnique) const
{
  CommandArgumentSpec copy(*this);
  copy.unique = mustBeUnique;
  return copy;
}

CommandArgumentSpec CommandArgumentSpec::withSelectionFallback(
  bool useSelection) const
{
  CommandArgumentSpec copy(*this);
  copy.selectionFallback = useSelection;
  return copy;
}

CommandArgumentSpec CommandArgumentSpec::withAlpha(bool allow) const
{
  CommandArgumentSpec copy(*this);
  copy.allowAlpha = allow;
  return copy;
}

// ---- CommandArguments ----------------------------------------------------

bool CommandArguments::has(const QString& name) const
{
  return m_values.contains(name) || m_atomLists.count(name) > 0;
}

const std::vector<Index>& CommandArguments::atoms(const QString& name) const
{
  static const std::vector<Index> none;
  const auto it = m_atomLists.find(name);
  return it == m_atomLists.end() ? none : it->second;
}

Index CommandArguments::atom(const QString& name) const
{
  return static_cast<Index>(m_values.value(name).toULongLong());
}

unsigned char CommandArguments::element(const QString& name) const
{
  return static_cast<unsigned char>(m_values.value(name).toUInt());
}

qlonglong CommandArguments::integer(const QString& name) const
{
  return m_values.value(name).toLongLong();
}

double CommandArguments::real(const QString& name) const
{
  return m_values.value(name).toDouble();
}

QString CommandArguments::string(const QString& name) const
{
  return m_values.value(name).toString();
}

bool CommandArguments::boolean(const QString& name) const
{
  return m_values.value(name).toBool();
}

Vector3 CommandArguments::vector3(const QString& name) const
{
  const QVariantList components = m_values.value(name).toList();
  if (components.size() != 3)
    return Vector3::Zero();
  return Vector3(components[0].toDouble(), components[1].toDouble(),
                 components[2].toDouble());
}

QColor CommandArguments::color(const QString& name) const
{
  return m_values.value(name).value<QColor>();
}

// ---- CommandRegistry -----------------------------------------------------

CommandRegistry::CommandRegistry(FailureCallback failureCallback)
  : m_failureCallback(std::move(failureCallback))
{
}

bool CommandRegistry::add(CommandSpec spec)
{
  if (spec.name.isEmpty()) {
    qWarning() << "CommandRegistry: refusing a command with no name.";
    return false;
  }
  if (contains(spec.name)) {
    qWarning() << "CommandRegistry: command" << spec.name
               << "is already registered; ignoring the duplicate.";
    return false;
  }

  // Options are looked up by name or alias, so every key must be unique
  // across the whole command or the schema and the handler would disagree.
  QSet<QString> seen;
  for (const auto& argument : spec.arguments) {
    QStringList keys{ argument.name };
    keys << argument.aliases;
    for (const auto& key : keys) {
      if (key.isEmpty()) {
        qWarning() << "CommandRegistry: command" << spec.name
                   << "has an option with an empty name or alias.";
        return false;
      }
      if (seen.contains(key)) {
        qWarning() << "CommandRegistry: command" << spec.name
                   << "uses the option name or alias" << key
                   << "more than once.";
        return false;
      }
      seen.insert(key);
    }
  }

  m_commands.push_back(std::move(spec));
  return true;
}

bool CommandRegistry::contains(const QString& name) const
{
  return spec(name) != nullptr;
}

QStringList CommandRegistry::names() const
{
  QStringList result;
  result.reserve(static_cast<qsizetype>(m_commands.size()));
  for (const auto& command : m_commands)
    result << command.name;
  return result;
}

void CommandRegistry::announce(
  const std::function<void(const QString& name, const QString& description)>&
    emitter) const
{
  for (const auto& command : m_commands)
    emitter(command.name, command.description);
}

const CommandSpec* CommandRegistry::spec(const QString& name) const
{
  const auto it =
    std::find_if(m_commands.begin(), m_commands.end(),
                 [&name](const CommandSpec& c) { return c.name == name; });
  return it == m_commands.end() ? nullptr : &*it;
}

QString CommandRegistry::description(const QString& name) const
{
  const CommandSpec* command = spec(name);
  return command != nullptr ? command->description : QString();
}

bool CommandRegistry::isAsync(const QString& name) const
{
  const CommandSpec* command = spec(name);
  return command != nullptr && command->async;
}

void CommandRegistry::fail(const QString& message) const
{
  if (m_failureCallback)
    m_failureCallback(message);
  else
    qWarning() << "CommandRegistry:" << message;
}

bool CommandRegistry::handle(const QString& command, const QVariantMap& options,
                             const Core::Molecule* molecule)
{
  const CommandSpec* found = spec(command);
  if (found == nullptr)
    return false;

  CommandArguments arguments;
  QString error;
  if (!validate(*found, options, molecule, arguments, error)) {
    fail(error);
    return true;
  }

  // Copy: a handler is free to register further commands.
  const auto handler = found->handler;
  if (handler)
    handler(arguments);
  return true;
}

bool CommandRegistry::validate(const CommandSpec& command,
                               const QVariantMap& options,
                               const Core::Molecule* molecule,
                               CommandArguments& out, QString& error) const
{
  if (command.needsMolecule && molecule == nullptr) {
    error = noMoleculeMessage();
    return false;
  }

  if (!command.allowUnknownOptions) {
    for (auto it = options.constBegin(); it != options.constEnd(); ++it) {
      if (!isKnownOption(command, it.key())) {
        error = tr("unknown option \"%1\" for command \"%2\".")
                  .arg(it.key())
                  .arg(command.name);
        return false;
      }
    }
  }

  for (const auto& argument : command.arguments) {
    // The name or alias that was given, and a second one if there is one.
    const QString* given = nullptr;
    const QString* extra = nullptr;
    const auto note = [&](const QString& key) {
      if (!options.contains(key))
        return;
      if (given == nullptr)
        given = &key;
      else if (extra == nullptr)
        extra = &key;
    };
    note(argument.name);
    for (const auto& alias : argument.aliases)
      note(alias);

    if (extra != nullptr) {
      error = tr("options \"%1\" and \"%2\" are the same option; give only "
                 "\"%1\".")
                .arg(argument.name)
                .arg(*extra);
      return false;
    }

    if (given == nullptr) {
      if (argument.type == CommandArgumentType::AtomIndices &&
          argument.selectionFallback) {
        if (molecule == nullptr) {
          error = noMoleculeMessage();
          return false;
        }
        std::vector<Index> selected;
        for (Index i = 0; i < molecule->atomCount(); ++i) {
          if (molecule->atomSelected(i))
            selected.push_back(i);
        }
        if (!countAcceptable(argument, selected.size())) {
          error = tr("%1 was not given, and the current selection (%n "
                     "atom(s)) does not have the number of atoms this "
                     "command needs.",
                     nullptr, static_cast<int>(selected.size()))
                    .arg(argument.name);
          return false;
        }
        out.m_atomLists[argument.name] = std::move(selected);
        continue;
      }
      if (argument.required) {
        error = tr("missing required option \"%1\".").arg(argument.name);
        return false;
      }
      if (argument.defaultValue.isValid() &&
          !convert(argument, argument.defaultValue, molecule, out.m_values,
                   out.m_atomLists, error))
        return false;
      continue;
    }

    if (!convert(argument, options.value(*given), molecule, out.m_values,
                 out.m_atomLists, error))
      return false;
  }

  return true;
}

bool CommandRegistry::parseAtomIndices(const QVariant& value,
                                       const CommandArgumentSpec& spec,
                                       const Core::Molecule& molecule,
                                       std::vector<Index>& out, QString& error)
{
  out.clear();

  if (value.typeId() != QMetaType::QVariantList) {
    error = tr("%1 must be a list of zero-based atom indices.").arg(spec.name);
    return false;
  }

  const QVariantList list = value.toList();
  if (!countAcceptable(spec, static_cast<size_t>(list.size()))) {
    error = countMessage(spec);
    return false;
  }

  const Index atomCount = molecule.atomCount();
  std::vector<Index> parsed;
  parsed.reserve(static_cast<size_t>(list.size()));
  std::vector<bool> seen;
  if (spec.unique)
    seen.assign(atomCount, false);

  for (qsizetype i = 0; i < list.size(); ++i) {
    Index index = 0;
    if (!parseOneIndex(list[i], static_cast<int>(i) + 1, spec.name, atomCount,
                       index, error))
      return false;

    if (spec.unique) {
      if (seen[index]) {
        error = tr("atom index %1 is repeated in %2; each atom must be "
                   "different.")
                  .arg(index)
                  .arg(spec.name);
        return false;
      }
      seen[index] = true;
    }
    parsed.push_back(index);
  }

  out = std::move(parsed);
  return true;
}

bool CommandRegistry::parseAtomIndex(const QVariant& value,
                                     const CommandArgumentSpec& spec,
                                     const Core::Molecule& molecule, Index& out,
                                     QString& error)
{
  return parseOneIndex(value, 0, spec.name, molecule.atomCount(), out, error);
}

bool CommandRegistry::parseElement(const QVariant& value, unsigned char& out,
                                   QString& error)
{
  const auto unknown = [&]() {
    error = tr("Unknown element \"%1\".").arg(value.toString());
    return false;
  };

  double number = 0.0;
  bool haveNumber = false;

  if (value.typeId() == QMetaType::QString) {
    const QString text = value.toString().trimmed();
    const unsigned char bySymbol =
      Core::Elements::atomicNumberFromSymbol(text.toStdString());
    // atomicNumberFromSymbol() also decodes any three-letter string as a
    // custom element (so "nan" would pass); only real elements are accepted.
    if (bySymbol != InvalidElement && bySymbol != 0 &&
        bySymbol < Core::Elements::elementCount()) {
      out = bySymbol;
      return true;
    }
    number = text.toDouble(&haveNumber);
  } else if (isNumericVariant(value)) {
    number = value.toDouble();
    haveNumber = true;
  }

  if (!haveNumber || !std::isfinite(number) || std::floor(number) != number)
    return unknown();

  const int maxNumber = static_cast<int>(Core::Elements::elementCount()) - 1;
  if (number < 1.0 || number > static_cast<double>(maxNumber)) {
    error = tr("Atomic number %1 is out of range (1 to %2).")
              .arg(number, 0, 'f', 0)
              .arg(maxNumber);
    return false;
  }

  out = static_cast<unsigned char>(number);
  return true;
}

QJsonObject CommandRegistry::schema(const QString& name) const
{
  const CommandSpec* command = spec(name);
  if (command == nullptr)
    return QJsonObject();

  QJsonObject properties;
  QJsonArray required;
  // Cross-key constraints for options with aliases, in argument order.
  QJsonArray constraints;
  for (const auto& argument : command->arguments) {
    const QJsonObject property = argumentSchema(argument);
    properties[argument.name] = property;

    if (argument.aliases.isEmpty()) {
      if (argument.required)
        required.append(argument.name);
    } else {
      // Runtime validation accepts only one of the name and its aliases.
      QStringList keys{ argument.name };
      keys << argument.aliases;
      QJsonObject constraint;
      if (argument.required) {
        // exactly one of the keys
        QJsonArray alternatives;
        for (const auto& key : keys) {
          QJsonObject alternative;
          alternative[QStringLiteral("required")] = QJsonArray{ key };
          alternatives.append(alternative);
        }
        constraint[QStringLiteral("oneOf")] = alternatives;
      } else {
        // at most one of the keys: no pair may appear together
        QJsonArray pairs;
        for (qsizetype i = 0; i < keys.size(); ++i) {
          for (qsizetype j = i + 1; j < keys.size(); ++j) {
            QJsonObject pair;
            pair[QStringLiteral("required")] = QJsonArray{ keys[i], keys[j] };
            pairs.append(pair);
          }
        }
        QJsonObject anyOf;
        anyOf[QStringLiteral("anyOf")] = pairs;
        constraint[QStringLiteral("not")] = anyOf;
      }
      constraints.append(constraint);
    }

    for (const auto& alias : argument.aliases) {
      QJsonObject aliasProperty = property;
      aliasProperty[QStringLiteral("deprecated")] = true;
      aliasProperty[QStringLiteral("description")] =
        QStringLiteral("Alias of %1.").arg(argument.name);
      properties[alias] = aliasProperty;
    }
  }

  QJsonObject result;
  result[QStringLiteral("type")] = QStringLiteral("object");
  result[QStringLiteral("description")] = command->description;
  result[QStringLiteral("properties")] = properties;
  result[QStringLiteral("required")] = required;
  if (!constraints.isEmpty())
    result[QStringLiteral("allOf")] = constraints;
  result[QStringLiteral("additionalProperties")] = command->allowUnknownOptions;
  result[QStringLiteral("x-avogadro-async")] = command->async;
  result[QStringLiteral("x-avogadro-needs-molecule")] = command->needsMolecule;
  return result;
}

} // namespace QtGui
} // namespace Avogadro
