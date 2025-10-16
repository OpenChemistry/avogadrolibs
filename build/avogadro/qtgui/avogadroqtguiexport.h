
#ifndef AVOGADROQTGUI_EXPORT_H
#define AVOGADROQTGUI_EXPORT_H

#ifdef AVOGADROQTGUI_STATIC_DEFINE
#  define AVOGADROQTGUI_EXPORT
#  define AVOGADROQTGUI_NO_EXPORT
#else
#  ifndef AVOGADROQTGUI_EXPORT
#    ifdef QtGui_EXPORTS
        /* We are building this library */
#      define AVOGADROQTGUI_EXPORT __attribute__((visibility("default")))
#    else
        /* We are using this library */
#      define AVOGADROQTGUI_EXPORT __attribute__((visibility("default")))
#    endif
#  endif

#  ifndef AVOGADROQTGUI_NO_EXPORT
#    define AVOGADROQTGUI_NO_EXPORT __attribute__((visibility("hidden")))
#  endif
#endif

#ifndef AVOGADROQTGUI_DEPRECATED
#  define AVOGADROQTGUI_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef AVOGADROQTGUI_DEPRECATED_EXPORT
#  define AVOGADROQTGUI_DEPRECATED_EXPORT AVOGADROQTGUI_EXPORT AVOGADROQTGUI_DEPRECATED
#endif

#ifndef AVOGADROQTGUI_DEPRECATED_NO_EXPORT
#  define AVOGADROQTGUI_DEPRECATED_NO_EXPORT AVOGADROQTGUI_NO_EXPORT AVOGADROQTGUI_DEPRECATED
#endif

/* NOLINTNEXTLINE(readability-avoid-unconditional-preprocessor-if) */
#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef AVOGADROQTGUI_NO_DEPRECATED
#    define AVOGADROQTGUI_NO_DEPRECATED
#  endif
#endif

#endif /* AVOGADROQTGUI_EXPORT_H */
