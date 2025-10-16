
#ifndef AVOGADRORENDERING_EXPORT_H
#define AVOGADRORENDERING_EXPORT_H

#ifdef AVOGADRORENDERING_STATIC_DEFINE
#  define AVOGADRORENDERING_EXPORT
#  define AVOGADRORENDERING_NO_EXPORT
#else
#  ifndef AVOGADRORENDERING_EXPORT
#    ifdef Rendering_EXPORTS
        /* We are building this library */
#      define AVOGADRORENDERING_EXPORT __attribute__((visibility("default")))
#    else
        /* We are using this library */
#      define AVOGADRORENDERING_EXPORT __attribute__((visibility("default")))
#    endif
#  endif

#  ifndef AVOGADRORENDERING_NO_EXPORT
#    define AVOGADRORENDERING_NO_EXPORT __attribute__((visibility("hidden")))
#  endif
#endif

#ifndef AVOGADRORENDERING_DEPRECATED
#  define AVOGADRORENDERING_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef AVOGADRORENDERING_DEPRECATED_EXPORT
#  define AVOGADRORENDERING_DEPRECATED_EXPORT AVOGADRORENDERING_EXPORT AVOGADRORENDERING_DEPRECATED
#endif

#ifndef AVOGADRORENDERING_DEPRECATED_NO_EXPORT
#  define AVOGADRORENDERING_DEPRECATED_NO_EXPORT AVOGADRORENDERING_NO_EXPORT AVOGADRORENDERING_DEPRECATED
#endif

/* NOLINTNEXTLINE(readability-avoid-unconditional-preprocessor-if) */
#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef AVOGADRORENDERING_NO_DEPRECATED
#    define AVOGADRORENDERING_NO_DEPRECATED
#  endif
#endif

#endif /* AVOGADRORENDERING_EXPORT_H */
