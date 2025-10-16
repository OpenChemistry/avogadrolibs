
#ifndef AVOGADROCALC_EXPORT_H
#define AVOGADROCALC_EXPORT_H

#ifdef AVOGADROCALC_STATIC_DEFINE
#  define AVOGADROCALC_EXPORT
#  define AVOGADROCALC_NO_EXPORT
#else
#  ifndef AVOGADROCALC_EXPORT
#    ifdef Calc_EXPORTS
        /* We are building this library */
#      define AVOGADROCALC_EXPORT __attribute__((visibility("default")))
#    else
        /* We are using this library */
#      define AVOGADROCALC_EXPORT __attribute__((visibility("default")))
#    endif
#  endif

#  ifndef AVOGADROCALC_NO_EXPORT
#    define AVOGADROCALC_NO_EXPORT __attribute__((visibility("hidden")))
#  endif
#endif

#ifndef AVOGADROCALC_DEPRECATED
#  define AVOGADROCALC_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef AVOGADROCALC_DEPRECATED_EXPORT
#  define AVOGADROCALC_DEPRECATED_EXPORT AVOGADROCALC_EXPORT AVOGADROCALC_DEPRECATED
#endif

#ifndef AVOGADROCALC_DEPRECATED_NO_EXPORT
#  define AVOGADROCALC_DEPRECATED_NO_EXPORT AVOGADROCALC_NO_EXPORT AVOGADROCALC_DEPRECATED
#endif

/* NOLINTNEXTLINE(readability-avoid-unconditional-preprocessor-if) */
#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef AVOGADROCALC_NO_DEPRECATED
#    define AVOGADROCALC_NO_DEPRECATED
#  endif
#endif

#endif /* AVOGADROCALC_EXPORT_H */
