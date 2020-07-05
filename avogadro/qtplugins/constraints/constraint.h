#include <QtCore>
#include <QJsonObject>
#include <QList>
//#include <avogadro/core/atom.h>
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
        Implementation of very simple class for the represenation of constraints.

        At the moment it stores rather naively just some numbers. The ConstraintType
        has the following mapping (reflected in the ConstraintDialog combobox):

        0: Ignore Atom
        1: Fix Atom
        2: Fix Atom X
        3: Fix Atom Y
        4: Fix Atom Z
        5: Distance
        6: Angle
        7: Torsion angle

        A more sophisticated way would probably be to store pointers to the respective
        atoms of the molecule and extend the Atom class by something like :

        void Atom::setConstrained()
        bool Atom::isConstrained()

        Connecting the appropriate signals  would enable easy updating of the constraints
        upon changing the Molecule.

        This constraint representation has to be translated when passing it to whatever
        Optimizing/MD/QM code.

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
      //      void SetAtomId(QList<int> atom_ids);
      void SetValue(double Value);

      int  GetConstraintType() const;
      double GetConstraintValue() const;
      /*
      int GetConstraintAtomA() const;
      int GetConstraintAtomB() const;
      int GetConstraintAtomC() const;
      int GetConstraintAtomD() const;
      */

      const Index GetConstraintAtomA() const;
      const Index GetConstraintAtomB() const;
      const Index GetConstraintAtomC() const;
      const Index GetConstraintAtomD() const;

      QJsonObject toJson();

      int ConstraintType;
      /*
      int AtomIdA;
      int AtomIdB;
      int AtomIdC;
      int AtomIdD;
      */

      /*
      Core::Atom* AtomA = nullptr;
      Core::Atom* AtomB = nullptr;
      Core::Atom* AtomC = nullptr;
      Core::Atom* AtomD = nullptr;
      */

      QList<Index> Atoms;
      double ConstraintValue;

      ConstraintsModel* c_model = nullptr;
    };    
  }
}
#endif
