
#ifndef AVOGADROQTOPENGL_EXPORT_H
#define AVOGADROQTOPENGL_EXPORT_H

#ifdef AVOGADROQTOPENGL_STATIC_DEFINE
#  define AVOGADROQTOPENGL_EXPORT
#  define AVOGADROQTOPENGL_NO_EXPORT
#else
#  ifndef AVOGADROQTOPENGL_EXPORT
#    ifdef QtOpenGL_EXPORTS
        /* We are building this library */
#      define AVOGADROQTOPENGL_EXPORT __attribute__((visibility("default")))
#    else
        /* We are using this library */
#      define AVOGADROQTOPENGL_EXPORT __attribute__((visibility("default")))
#    endif
#  endif

#  ifndef AVOGADROQTOPENGL_NO_EXPORT
#    define AVOGADROQTOPENGL_NO_EXPORT __attribute__((visibility("hidden")))
#  endif
#endif

#ifndef AVOGADROQTOPENGL_DEPRECATED
#  define AVOGADROQTOPENGL_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef AVOGADROQTOPENGL_DEPRECATED_EXPORT
#  define AVOGADROQTOPENGL_DEPRECATED_EXPORT AVOGADROQTOPENGL_EXPORT AVOGADROQTOPENGL_DEPRECATED
#endif

#ifndef AVOGADROQTOPENGL_DEPRECATED_NO_EXPORT
#  define AVOGADROQTOPENGL_DEPRECATED_NO_EXPORT AVOGADROQTOPENGL_NO_EXPORT AVOGADROQTOPENGL_DEPRECATED
#endif

/* NOLINTNEXTLINE(readability-avoid-unconditional-preprocessor-if) */
#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef AVOGADROQTOPENGL_NO_DEPRECATED
#    define AVOGADROQTOPENGL_NO_DEPRECATED
#  endif
#endif

#endif /* AVOGADROQTOPENGL_EXPORT_H */
