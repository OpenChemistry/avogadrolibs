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
  Integer,
  Real,
  String,
  Enum,
  Bool,
  Vector3 ///< list of exactly three finite numbers [x, y, z]
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
  QString name;
  QString description; ///< already translated by the caller
  CommandArgumentType type = CommandArgumentType::String;
  bool required = false;
  QVariant defaultValue; ///< invalid QVariant means "no default"

  /** Deprecated alternative names. Giving the name and an alias is an error. */
  QStringList aliases;

  /** Inclusive limits for Integer and Real. */
  std::optional<double> minimum;
  std::optional<double> maximum;

  /** AtomIndices: number of indices. maxCount < 0 means unlimited, and
   *  minCount == maxCount means "exactly". */
  int minCount = 0;
  int maxCount = -1;
  bool unique = true;

  /** AtomIndices: when the option is absent, use the selected atoms. */
  bool selectionFallback = false;

  /** Enum: the accepted values, matched case-sensitively. */
  QStringList allowedValues;

  static CommandArgumentSpec atomIndices(const QString& name,
                                         const QString& description);
  static CommandArgumentSpec atomIndex(const QString& name,
                                       const QString& description);
  static CommandArgumentSpec element(const QString& name,
                                     const QString& description);
  static CommandArgumentSpec integer(const QString& name,
                                     const QString& description);
  static CommandArgumentSpec real(const QString& name,
                                  const QString& description);
  static CommandArgumentSpec string(const QString& name,
                                    const QString& description);
  static CommandArgumentSpec enumeration(const QString& name,
                                         const QString& description,
                                         const QStringList& allowedValues);
  static CommandArgumentSpec boolean(const QString& name,
                                     const QString& description);
  static CommandArgumentSpec vector3(const QString& name,
                                     const QString& description);

  CommandArgumentSpec withRequired(bool isRequired = true) const;
  CommandArgumentSpec withDefault(const QVariant& value) const;
  CommandArgumentSpec withAliases(const QStringList& aliasNames) const;
  CommandArgumentSpec withRange(std::optional<double> minimumValue,
                                std::optional<double> maximumValue) const;
  /** An exact count when @p minimumCount == @p maximumCount. */
  CommandArgumentSpec withCount(int minimumCount, int maximumCount) const;
  CommandArgumentSpec withUnique(bool mustBeUnique) const;
  CommandArgumentSpec withSelectionFallback(bool useSelection = true) const;
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
  bool has(const QString& name) const;

  const std::vector<Index>& atoms(const QString& name) const;
  Index atom(const QString& name) const;
  unsigned char element(const QString& name) const;
  qlonglong integer(const QString& name) const;
  double real(const QString& name) const;
  QString string(const QString& name) const;
  bool boolean(const QString& name) const;
  Vector3 vector3(const QString& name) const;

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
  QString name;
  QString description;
  std::vector<CommandArgumentSpec> arguments;

  /** Metadata only: the handler will emit commandStarted() and finish later. */
  bool async = false;

  /** Refuse the command up front when no molecule is open. */
  bool needsMolecule = true;

  /** If false, an option that is not in @c arguments is an error. */
  bool allowUnknownOptions = false;

  /** Called with validated arguments. It must emit commandFinished() or
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
 */
class AVOGADROQTGUI_EXPORT CommandRegistry
{
  Q_DECLARE_TR_FUNCTIONS(CommandRegistry)

public:
  using FailureCallback = std::function<void(const QString& message)>;

  /** @param failureCallback receives validation failures; without one they
   *  go to qWarning(). */
  explicit CommandRegistry(FailureCallback failureCallback = nullptr);

  /** Register @p spec. Returns false (and warns) if the name is empty or
   *  already registered; the first registration wins. */
  bool add(CommandSpec spec);

  bool contains(const QString& name) const;
  QStringList names() const; ///< in registration order
  QString description(const QString& name) const;
  bool isAsync(const QString& name) const;

  /** Call @p emitter with each command's name and description, in
   *  registration order (plugins use it to emit registerCommand()). */
  void announce(
    const std::function<void(const QString& name, const QString& description)>&
      emitter) const;

  /** The spec, or nullptr. Invalidated by the next add(). */
  const CommandSpec* spec(const QString& name) const;

  /**
   * Validate @p options and run the handler.
   * @return false only if @p command is not registered; a validation
   * failure is reported through the failure callback and returns true.
   */
  bool handle(const QString& command, const QVariantMap& options,
              const Core::Molecule* molecule);

  /** JSON Schema for the options object of @p name, or {} if unknown. */
  QJsonObject schema(const QString& name) const;

  /** @name Validators, usable without a registry.
   *  Each returns false and fills @p error (translated) on failure.
   *  @{ */
  static bool parseAtomIndices(const QVariant& value,
                               const CommandArgumentSpec& spec,
                               const Core::Molecule& molecule,
                               std::vector<Index>& out, QString& error);
  static bool parseAtomIndex(const QVariant& value,
                             const CommandArgumentSpec& spec,
                             const Core::Molecule& molecule, Index& out,
                             QString& error);
  static bool parseElement(const QVariant& value, unsigned char& out,
                           QString& error);
  /** @} */

private:
  bool validate(const CommandSpec& command, const QVariantMap& options,
                const Core::Molecule* molecule, CommandArguments& out,
                QString& error) const;
  void fail(const QString& message) const;

  FailureCallback m_failureCallback;
  std::vector<CommandSpec> m_commands;
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_COMMANDREGISTRY_H
