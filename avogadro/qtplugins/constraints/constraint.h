#include <QtCore>
#include <QJsonObject>
#include <QList>

#include <avogadro/qtgui/molecule.h>
#include "constraintsmodel.h"

#ifndef CONSTRAINT_H
#define CONSTRAINT_H

namespace Avogadro {
  namespace Core{
    class Atom;
  }
  namespace QtPlugins {
    class Constraint
    {
    public:
      /*
        Implementation of simple class for the represenation of constraints.

        The ConstraintType has the following mapping (reflected in the ConstraintDialog combobox):

        0: Ignore Atom
        1: Fix Atom
        2: Fix Atom X
        3: Fix Atom Y
        4: Fix Atom Z
        5: Distance
        6: Angle
        7: Torsion

        This implementation makes use of the UniqueID that is assigned to each Atom upon creation,
        which can be used to unambigously retrieve the current index of the Atom in molecule.

        This constraint representation has to be translated into package specific instructions when
        passing it to whatever Optimizing/MD/QM code.

       */
      explicit Constraint(int ConstraintType,
                          int AtomIdA,
                          int AtomIdB,
                          int AtomIdC,
                          int AtomIdD,
                          double ConstraintValue,
                          ConstraintsModel* model);
      ~Constraint();

      void SetConstraintType(int ConstraintType);
      void SetValue(double Value);

      int  GetConstraintType() const;
      double GetConstraintValue() const;

      const Index GetConstraintAtomA() const;
      const Index GetConstraintAtomB() const;
      const Index GetConstraintAtomC() const;
      const Index GetConstraintAtomD() const;

      QJsonObject toJson();

      int ConstraintType;
      double ConstraintValue;

      QList<Index> Atoms;
      ConstraintsModel* c_model = nullptr;
    };    
  }
}
#endif
