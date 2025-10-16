
#ifndef AVOGADROQTPLUGINS_EXPORT_H
#define AVOGADROQTPLUGINS_EXPORT_H

#ifdef AVOGADROQTPLUGINS_STATIC_DEFINE
#  define AVOGADROQTPLUGINS_EXPORT
#  define AVOGADROQTPLUGINS_NO_EXPORT
#else
#  ifndef AVOGADROQTPLUGINS_EXPORT
#    ifdef QtPlugins_EXPORTS
        /* We are building this library */
#      define AVOGADROQTPLUGINS_EXPORT __attribute__((visibility("default")))
#    else
        /* We are using this library */
#      define AVOGADROQTPLUGINS_EXPORT __attribute__((visibility("default")))
#    endif
#  endif

#  ifndef AVOGADROQTPLUGINS_NO_EXPORT
#    define AVOGADROQTPLUGINS_NO_EXPORT __attribute__((visibility("hidden")))
#  endif
#endif

#ifndef AVOGADROQTPLUGINS_DEPRECATED
#  define AVOGADROQTPLUGINS_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef AVOGADROQTPLUGINS_DEPRECATED_EXPORT
#  define AVOGADROQTPLUGINS_DEPRECATED_EXPORT AVOGADROQTPLUGINS_EXPORT AVOGADROQTPLUGINS_DEPRECATED
#endif

#ifndef AVOGADROQTPLUGINS_DEPRECATED_NO_EXPORT
#  define AVOGADROQTPLUGINS_DEPRECATED_NO_EXPORT AVOGADROQTPLUGINS_NO_EXPORT AVOGADROQTPLUGINS_DEPRECATED
#endif

/* NOLINTNEXTLINE(readability-avoid-unconditional-preprocessor-if) */
#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef AVOGADROQTPLUGINS_NO_DEPRECATED
#    define AVOGADROQTPLUGINS_NO_DEPRECATED
#  endif
#endif

#endif /* AVOGADROQTPLUGINS_EXPORT_H */
