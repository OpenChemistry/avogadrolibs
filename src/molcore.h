#ifndef MOLCORE_MOLCORE_H
#define MOLCORE_MOLCORE_H

#define MOLCORE_EXPORT

/// This macro marks a parameter as unused. Its purpose is to
/// disable the compiler from emitting unused parameter warnings.
#define MOLCORE_UNUSED(variable) (void) variable

/// This macro marks a class as not copyable. It should be used in
/// the private section of a class's declaration.
#define MOLCORE_DISABLE_COPY(Class) \
  Class(const Class&); \
  Class& operator=(const Class&);

namespace MolCore {

/// Typedef for a real number.
typedef double Real;

} // end MolCore namespace

#endif // MOLCORE_MOLCORE_H
