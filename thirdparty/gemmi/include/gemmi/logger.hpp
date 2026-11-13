// Copyright Global Phasing Ltd.
//
// Logger - a tiny utility for passing messages through a callback.

#ifndef GEMMI_LOGGER_HPP_
#define GEMMI_LOGGER_HPP_

#include <cstdio>      // for fprintf
#include <functional>  // for function
#include "fail.hpp"    // for GEMMI_COLD
#include "util.hpp"    // for cat

namespace gemmi {

/// @brief Logger for passing messages through callbacks with severity levels.
/// @details Messages are passed as strings without a trailing newline.
/// They have syslog-like severity levels: 8=debug, 6=info, 5=notice, 3=error,
/// allowing the use of a threshold to filter them.
/// Quirk: Errors double as both errors and warnings. Unrecoverable errors
/// don't go through this class; Logger only handles errors that can
/// be downgraded to warnings. If a callback is set, the error is passed
/// as a warning message. Otherwise, it's thrown as std::runtime_error.
struct Logger {
  /// @brief Callback function that handles each logged message.
  std::function<void(const std::string&)> callback;

  /// @brief Severity threshold for filtering messages.
  /// @details Pass messages of this level and all lower (more severe) levels:
  /// 8=all, 6=all but debug, 5=notes and warnings, 3=warnings, 0=none
  int threshold = 6;

  /// @brief Temporarily suspend message logging.
  /// @details Used internally to avoid duplicate messages when the same function
  /// is called (internally) multiple times.
  void suspend() { threshold -= 100; }

  /// @brief Resume message logging after suspension.
  void resume()  { threshold += 100; }

  /// @brief Send a message at a specific severity level.
  /// @tparam N Severity level threshold for this message
  /// @param args Message content to concatenate and send
  template<int N, class... Args> void level(Args const&... args) const {
    if (threshold >= N && callback)
      callback(cat(args...));
  }

  /// @brief Send a debug message.
  /// @param args Message content
  template<class... Args> void debug(Args const&... args) const { level<8>("Debug: ", args...); }

  /// @brief Send an informational message without prefix.
  /// @param args Message content
  template<class... Args> void mesg(Args const&... args) const { level<6>(args...); }

  /// @brief Send a note (notice-level significant message).
  /// @param args Message content
  template<class... Args> void note(Args const&... args) const { level<5>("Note: ", args...); }

  /// @brief Send a warning or error message.
  /// @details If callback is set, sends as warning; otherwise throws exception.
  /// @param args Message content
  template<class... Args> GEMMI_COLD void err(Args const&... args) const {
    if (threshold >= 3) {
      std::string msg = cat(args...);
      if (callback == nullptr)
        fail(msg);
      callback("Warning: " + msg);
    }
  }

  /// @brief Predefined callback function to print messages to stderr.
  /// @details Use as: logger.callback = Logger::to_stderr;
  /// @param s Message string (printed with newline)
  static void to_stderr(const std::string& s) {
    std::fprintf(stderr, "%s\n", s.c_str());
  }

  /// @brief Predefined callback function to print messages to stdout.
  /// @details Use as: logger.callback = Logger::to_stdout;
  /// @param s Message string (printed with newline)
  static void to_stdout(const std::string& s) {
    std::fprintf(stdout, "%s\n", s.c_str());
  }
};

} // namespace gemmi
#endif
