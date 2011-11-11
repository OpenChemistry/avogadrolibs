#ifndef MOLCORE_VARIANTMAP_H
#define MOLCORE_VARIANTMAP_H

#include "molcore.h"

#include "variant.h"

#include <map>
#include <string>

namespace MolCore {

class MOLCORE_EXPORT VariantMap
{
public:
  // construction and destruction
  VariantMap();
  ~VariantMap();

  // properties
  size_t size() const;
  bool isEmpty() const;

  // values
  void setValue(const std::string &name, const Variant &v);
  Variant value(const std::string &name) const;

private:
  std::map<std::string, Variant> m_map;
};

} // end MolCore namespace

#endif // MOLCORE_VARIANTMAP_H
