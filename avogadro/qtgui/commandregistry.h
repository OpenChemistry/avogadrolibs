/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_COMMANDREGISTRY_H
#define AVOGADRO_QTGUI_COMMANDREGISTRY_H

#include "avogadroqtguiexport.h"

#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/vector.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QJsonObject>
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtCore/QVariant>
#include <QtCore/QVariantMap>

#include <functional>
#include <map>
#include <optional>
#include <vector>

class QColor;

namespace Avogadro {
namespace Core {
class Molecule;
}

namespace QtGui {

/** The kinds of option a command can take. */
enum class CommandArgumentType
{
  AtomIndices, ///< list of zero-based atom indices
  AtomIndex,   ///< one zero-based atom index
  Element,     ///< atomic number, numeric string or symbol
  Integer,     ///< whole number, optionally limited by a range
  Real,        ///< finite number, optionally limited by a range
  String,      ///< any string
  Enum,        ///< one of a fixed set of strings
  Bool,        ///< true or false (not 0 or 1)
  Vector3,     ///< list of exactly three finite numbers [x, y, z]
  Color        ///< "#RRGGBB" hex, a color name, or [r, g, b] (0-255)
};

/**
 * @class CommandArgumentSpec commandregistry.h
 * <avogadro/qtgui/commandregistry.h>
 * @brief Describes one option of a command: its name, type and limits.
 *
 * Build one with the static factories and chain the @c with*() members,
 * each of which returns a modified copy:
 * @code
 * auto atoms = CommandArgumentSpec::atomIndices(
 *                "atoms", tr("Atoms to measure."))
 *                .withCount(2, 4)
 *                .withAliases({ "indices" });
 * @endcode
 */
struct AVOGADROQTGUI_EXPORT CommandArgumentSpec
{
  /** The option's key in the RPC options object. */
  QString name;
  QString description; ///< already translated by the caller
  CommandArgumentType type = CommandArgumentType::String;
  /** If true, leaving the option out is an error (see also defaultValue). */
  bool required = false;
  /** Used when the option is absent and not required. It goes through the
   *  same validation as a caller's value. An invalid QVariant means "no
   *  default". */
  QVariant defaultValue;

  /** Deprecated alternative names. Giving the name and an alias is an error. */
  QStringList aliases;

  /** Display unit for Integer, Real and Vector3, e.g. "Å" or "°". Shown in
   *  range errors (and the Vector3 format error) and exported as
   *  "x-avogadro-unit". Not translated. */
  QString unit;

  /** Inclusive limits for Integer and Real. */
  std::optional<double> minimum;
  std::optional<double> maximum; ///< see minimum

  /** AtomIndices: number of indices. maxCount < 0 means unlimited, and
   *  minCount == maxCount means "exactly". */
  int minCount = 0;
  int maxCount = -1; ///< see minCount
  /** AtomIndices: if true (the default), a repeated index is an error. */
  bool unique = true;

  /** AtomIndices: when the option is absent, use the selected atoms. */
  bool selectionFallback = false;

  /** Color: also accept an alpha channel, as "#RRGGBBAA" / "#RGBA" (CSS
   *  order, alpha last), the name "transparent", or [r, g, b, a]. */
  bool allowAlpha = false;

  /** Enum: the accepted values, matched case-sensitively. */
  QStringList allowedValues;

  /** A list of zero-based atom indices (numbers, never strings). */
  static CommandArgumentSpec atomIndices(const QString& name,
                                         const QString& description);
  /** One zero-based atom index. */
  static CommandArgumentSpec atomIndex(const QString& name,
                                       const QString& description);
  /** An element: atomic number, numeric string ("6") or symbol ("C"). */
  static CommandArgumentSpec element(const QString& name,
                                     const QString& description);
  /** A whole number; floats with an integer value are accepted. */
  static CommandArgumentSpec integer(const QString& name,
                                     const QString& description);
  /** A finite number (NaN and infinity are rejected). */
  static CommandArgumentSpec real(const QString& name,
                                  const QString& description);
  /** A string; numbers are not converted. */
  static CommandArgumentSpec string(const QString& name,
                                    const QString& description);
  /** One of @p allowedValues, matched case-sensitively. */
  static CommandArgumentSpec enumeration(const QString& name,
                                         const QString& description,
                                         const QStringList& allowedValues);
  /** true or false; 0, 1 and strings are rejected. */
  static CommandArgumentSpec boolean(const QString& name,
                                     const QString& description);
  /** A list of exactly three finite numbers [x, y, z]. */
  static CommandArgumentSpec vector3(const QString& name,
                                     const QString& description);
  /** A color: "#RGB" / "#RRGGBB", a CSS color name, or [r, g, b] with whole
   *  values 0-255. See withAlpha() for transparency. */
  static CommandArgumentSpec color(const QString& name,
                                   const QString& description);

  /** @return A copy with required set (the option must be given). */
  CommandArgumentSpec withRequired(bool isRequired = true) const;
  /** @return A copy with the default used when the option is absent. */
  CommandArgumentSpec withDefault(const QVariant& value) const;
  /** @return A copy that also accepts the deprecated names @p aliasNames.
   *  They resolve to the canonical name; giving two of them is an error. */
  CommandArgumentSpec withAliases(const QStringList& aliasNames) const;
  /** @return A copy with the display unit @p unitText, e.g. "Å" or "°".
   *  Angle symbols (° ′ ″) are written directly after the number in
   *  messages, other units after a space. The unit is not translated. */
  CommandArgumentSpec withUnit(const QString& unitText) const;
  /** @return A copy with inclusive limits for Integer and Real. Pass
   *  std::nullopt for a side with no limit. */
  CommandArgumentSpec withRange(std::optional<double> minimumValue,
                                std::optional<double> maximumValue) const;
  /** @return A copy limiting an AtomIndices list to
   *  [@p minimumCount, @p maximumCount] entries (maximum < 0: no limit).
   *  An exact count when @p minimumCount == @p maximumCount. */
  CommandArgumentSpec withCount(int minimumCount, int maximumCount) const;
  /** @return A copy that does (or, if false, does not) reject repeated
   *  atom indices. */
  CommandArgumentSpec withUnique(bool mustBeUnique) const;
  /** @return A copy that uses the selected atoms, in index order, when the
   *  option is absent. The count limits still apply to the selection. */
  CommandArgumentSpec withSelectionFallback(bool useSelection = true) const;
  /** @return A copy whose Color also accepts an alpha channel. */
  CommandArgumentSpec withAlpha(bool allow = true) const;
};

/**
 * @class CommandArguments commandregistry.h
 * <avogadro/qtgui/commandregistry.h>
 * @brief The validated, converted options passed to a command handler.
 *
 * Defaults have been applied and aliases resolved to the canonical name.
 * Getters for an option that was neither given nor defaulted return an
 * empty / zero value; use has() to tell.
 */
class AVOGADROQTGUI_EXPORT CommandArguments
{
public:
  /** @return Whether @p name was given or defaulted. */
  bool has(const QString& name) const;

  /** @return The atom indices, in the order given; empty if absent. */
  const std::vector<Index>& atoms(const QString& name) const;
  /** @return The atom index; 0 if absent. */
  Index atom(const QString& name) const;
  /** @return The atomic number (1 to the last element); 0 if absent. */
  unsigned char element(const QString& name) const;
  /** @return The whole number; 0 if absent. */
  qlonglong integer(const QString& name) const;
  /** @return The number; 0.0 if absent. */
  double real(const QString& name) const;
  /** @return The string (or enum value); empty if absent. */
  QString string(const QString& name) const;
  /** @return The boolean; false if absent. */
  bool boolean(const QString& name) const;
  /** @return The vector; (0, 0, 0) if absent. */
  Vector3 vector3(const QString& name) const;
  /** @return The color, with alpha 255 unless the caller gave one; an
   *  invalid QColor if absent. Include <QtGui/QColor> to use it. */
  QColor color(const QString& name) const;

private:
  friend class CommandRegistry;

  /// Converted scalars. A Vector3 is kept as a QVariantList of three doubles,
  /// which needs no extra map and keeps has() correct.
  QVariantMap m_values;
  std::map<QString, std::vector<Index>> m_atomLists;
};

/**
 * @class CommandSpec commandregistry.h <avogadro/qtgui/commandregistry.h>
 * @brief A command: name, description, typed options and a handler.
 */
struct AVOGADROQTGUI_EXPORT CommandSpec
{
  /** The command name, as the app and scripts call it. Must be unique. */
  QString name;
  QString description; ///< already translated by the caller
  /** The options, validated in this order. */
  std::vector<CommandArgumentSpec> arguments;

  /** Metadata only: the handler will emit commandStarted() and finish later. */
  bool async = false;

  /** Refuse the command up front when no molecule is open. */
  bool needsMolecule = true;

  /** If false, an option that is not in @c arguments is an error. */
  bool allowUnknownOptions = false;

  /** Called with validated arguments. May be empty (the command then only
   *  validates). It must emit commandFinished() or
   *  commandFailed() itself. */
  std::function<void(const CommandArguments&)> handler;
};

/**
 * @class CommandRegistry commandregistry.h <avogadro/qtgui/commandregistry.h>
 * @brief Validated, self-describing plugin commands.
 *
 * A plugin registers CommandSpec entries; handle() checks the RPC options
 * against the spec (reporting any problem as one translated message through
 * the failure callback) and only then calls the handler. schema() exports a
 * spec as JSON Schema (draft 2020-12).
 *
 * Command names share one flat namespace, so add() rejects a duplicate.
 * add() also rejects a command with an empty option name or with any option
 * name or alias used more than once, since options are looked up by either.
 */
class AVOGADROQTGUI_EXPORT CommandRegistry
{
  Q_DECLARE_TR_FUNCTIONS(CommandRegistry)

public:
  /** Receives the one translated message for a failed validation. */
  using FailureCallback = std::function<void(const QString& message)>;

  /** @param failureCallback receives validation failures; without one they
   *  go to qWarning(). In a plugin this is usually a lambda that emits
   *  commandFailed(). */
  explicit CommandRegistry(FailureCallback failureCallback = nullptr);

  /** Register @p spec. Returns false (and warns) if the name is empty or
   *  already registered; the first registration wins. */
  bool add(CommandSpec spec);

  /** @return Whether a command called @p name is registered. */
  bool contains(const QString& name) const;
  /** @return The command names, in registration order. */
  QStringList names() const;
  /** @return The description of @p name; empty if it is not registered. */
  QString description(const QString& name) const;
  /** @return Whether @p name is marked async (metadata only); false if it is
   *  not registered. */
  bool isAsync(const QString& name) const;

  /** Call @p emitter with each command's name and description, in
   *  registration order (plugins use it to emit registerCommand()). */
  void announce(
    const std::function<void(const QString& name, const QString& description)>&
      emitter) const;

  /** @return The spec of @p name, or nullptr. The pointer is invalidated by
   *  the next add(). */
  const CommandSpec* spec(const QString& name) const;

  /**
   * Validate @p options and run the handler.
   * @param molecule The current molecule. May be null: a command that needs
   * a molecule then fails with "No molecule" before anything else is checked.
   * @return false only if @p command is not registered; a validation
   * failure is reported through the failure callback and returns true.
   */
  bool handle(const QString& command, const QVariantMap& options,
              const Core::Molecule* molecule);

  /** @return A JSON Schema (draft 2020-12) for the options object of
   *  @p name, or {} if it is not registered. Aliases appear as deprecated
   *  properties; "x-avogadro-async" and "x-avogadro-needs-molecule" carry
   *  the metadata flags. A required option with aliases needs exactly one of
   *  its name and aliases ("oneOf"); an optional one allows at most one
   *  ("not" + "anyOf" over each pair). These constraints are collected in a
   *  top-level "allOf", in argument order. */
  QJsonObject schema(const QString& name) const;

  /** @name Validators, usable without a registry.
   *  Each returns false and fills @p error (translated) on failure.
   *  @{ */

  /** Check a list of atom indices against @p spec's count and uniqueness
   *  limits and the atoms in @p molecule. Numbers only (bools and strings
   *  are rejected); values are compared as doubles before casting, so huge
   *  values cannot overflow. @p out is cleared first. */
  static bool parseAtomIndices(const QVariant& value,
                               const CommandArgumentSpec& spec,
                               const Core::Molecule& molecule,
                               std::vector<Index>& out, QString& error);
  /** As parseAtomIndices(), for one index. */
  static bool parseAtomIndex(const QVariant& value,
                             const CommandArgumentSpec& spec,
                             const Core::Molecule& molecule, Index& out,
                             QString& error);
  /** Accept an atomic number (whole number, or a numeric string) or an
   *  element symbol. Zero, out-of-range numbers, bools and custom elements
   *  are rejected. */
  static bool parseElement(const QVariant& value, unsigned char& out,
                           QString& error);
  /** @} */

private:
  /** Check @p options against @p command, in this order: a molecule if one
   *  is needed, unknown options, then each argument in turn (alias
   *  conflicts, selection fallback, required, default, conversion). Fills
   *  @p out on success and @p error on failure. */
  bool validate(const CommandSpec& command, const QVariantMap& options,
                const Core::Molecule* molecule, CommandArguments& out,
                QString& error) const;
  /** Report @p message through the failure callback, or qWarning() if there
   *  is none. */
  void fail(const QString& message) const;

  FailureCallback m_failureCallback;   ///< may be empty
  std::vector<CommandSpec> m_commands; ///< in registration order
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_COMMANDREGISTRY_H
