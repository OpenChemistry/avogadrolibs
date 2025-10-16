
#ifndef AVOGADROMOLEQUEUE_EXPORT_H
#define AVOGADROMOLEQUEUE_EXPORT_H

#ifdef AVOGADROMOLEQUEUE_STATIC_DEFINE
#  define AVOGADROMOLEQUEUE_EXPORT
#  define AVOGADROMOLEQUEUE_NO_EXPORT
#else
#  ifndef AVOGADROMOLEQUEUE_EXPORT
#    ifdef MoleQueue_EXPORTS
        /* We are building this library */
#      define AVOGADROMOLEQUEUE_EXPORT __attribute__((visibility("default")))
#    else
        /* We are using this library */
#      define AVOGADROMOLEQUEUE_EXPORT __attribute__((visibility("default")))
#    endif
#  endif

#  ifndef AVOGADROMOLEQUEUE_NO_EXPORT
#    define AVOGADROMOLEQUEUE_NO_EXPORT __attribute__((visibility("hidden")))
#  endif
#endif

#ifndef AVOGADROMOLEQUEUE_DEPRECATED
#  define AVOGADROMOLEQUEUE_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef AVOGADROMOLEQUEUE_DEPRECATED_EXPORT
#  define AVOGADROMOLEQUEUE_DEPRECATED_EXPORT AVOGADROMOLEQUEUE_EXPORT AVOGADROMOLEQUEUE_DEPRECATED
#endif

#ifndef AVOGADROMOLEQUEUE_DEPRECATED_NO_EXPORT
#  define AVOGADROMOLEQUEUE_DEPRECATED_NO_EXPORT AVOGADROMOLEQUEUE_NO_EXPORT AVOGADROMOLEQUEUE_DEPRECATED
#endif

/* NOLINTNEXTLINE(readability-avoid-unconditional-preprocessor-if) */
#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef AVOGADROMOLEQUEUE_NO_DEPRECATED
#    define AVOGADROMOLEQUEUE_NO_DEPRECATED
#  endif
#endif

#endif /* AVOGADROMOLEQUEUE_EXPORT_H */
