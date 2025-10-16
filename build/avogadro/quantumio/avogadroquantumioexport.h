
#ifndef AVOGADROQUANTUMIO_EXPORT_H
#define AVOGADROQUANTUMIO_EXPORT_H

#ifdef AVOGADROQUANTUMIO_STATIC_DEFINE
#  define AVOGADROQUANTUMIO_EXPORT
#  define AVOGADROQUANTUMIO_NO_EXPORT
#else
#  ifndef AVOGADROQUANTUMIO_EXPORT
#    ifdef QuantumIO_EXPORTS
        /* We are building this library */
#      define AVOGADROQUANTUMIO_EXPORT __attribute__((visibility("default")))
#    else
        /* We are using this library */
#      define AVOGADROQUANTUMIO_EXPORT __attribute__((visibility("default")))
#    endif
#  endif

#  ifndef AVOGADROQUANTUMIO_NO_EXPORT
#    define AVOGADROQUANTUMIO_NO_EXPORT __attribute__((visibility("hidden")))
#  endif
#endif

#ifndef AVOGADROQUANTUMIO_DEPRECATED
#  define AVOGADROQUANTUMIO_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef AVOGADROQUANTUMIO_DEPRECATED_EXPORT
#  define AVOGADROQUANTUMIO_DEPRECATED_EXPORT AVOGADROQUANTUMIO_EXPORT AVOGADROQUANTUMIO_DEPRECATED
#endif

#ifndef AVOGADROQUANTUMIO_DEPRECATED_NO_EXPORT
#  define AVOGADROQUANTUMIO_DEPRECATED_NO_EXPORT AVOGADROQUANTUMIO_NO_EXPORT AVOGADROQUANTUMIO_DEPRECATED
#endif

/* NOLINTNEXTLINE(readability-avoid-unconditional-preprocessor-if) */
#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef AVOGADROQUANTUMIO_NO_DEPRECATED
#    define AVOGADROQUANTUMIO_NO_DEPRECATED
#  endif
#endif

#endif /* AVOGADROQUANTUMIO_EXPORT_H */
