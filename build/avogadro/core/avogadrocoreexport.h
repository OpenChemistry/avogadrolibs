
#ifndef AVOGADROCORE_EXPORT_H
#define AVOGADROCORE_EXPORT_H

#ifdef AVOGADROCORE_STATIC_DEFINE
#  define AVOGADROCORE_EXPORT
#  define AVOGADROCORE_NO_EXPORT
#else
#  ifndef AVOGADROCORE_EXPORT
#    ifdef Core_EXPORTS
        /* We are building this library */
#      define AVOGADROCORE_EXPORT __attribute__((visibility("default")))
#    else
        /* We are using this library */
#      define AVOGADROCORE_EXPORT __attribute__((visibility("default")))
#    endif
#  endif

#  ifndef AVOGADROCORE_NO_EXPORT
#    define AVOGADROCORE_NO_EXPORT __attribute__((visibility("hidden")))
#  endif
#endif

#ifndef AVOGADROCORE_DEPRECATED
#  define AVOGADROCORE_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef AVOGADROCORE_DEPRECATED_EXPORT
#  define AVOGADROCORE_DEPRECATED_EXPORT AVOGADROCORE_EXPORT AVOGADROCORE_DEPRECATED
#endif

#ifndef AVOGADROCORE_DEPRECATED_NO_EXPORT
#  define AVOGADROCORE_DEPRECATED_NO_EXPORT AVOGADROCORE_NO_EXPORT AVOGADROCORE_DEPRECATED
#endif

/* NOLINTNEXTLINE(readability-avoid-unconditional-preprocessor-if) */
#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef AVOGADROCORE_NO_DEPRECATED
#    define AVOGADROCORE_NO_DEPRECATED
#  endif
#endif

#endif /* AVOGADROCORE_EXPORT_H */
