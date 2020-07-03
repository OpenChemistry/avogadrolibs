#include <QtCore>
#include <QJsonObject>

namespace Avogadro {
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

        This constraint representation has to be translated when passing it to whatever
        Optimizing/MD/QM code.

        A more sophisticated way would probably be to store pointers to the respective
        atoms of the molecule and extend the Atom class by something like :

        void Atom::setConstrained()
        bool Atom::isConstrained()

        This would enable easy updating of the constraints upon changing the Molecule.


       */
      explicit Constraint(int ConstraintType,
                          int AtomIdA,
                          int AtomIdB,
                          int AtomIdC,
                          int AtomIdD,
                          double ConstraintValue);
      ~Constraint();

      void SetConstraintType(int ConstraintType);
      //      void SetAtomId(QList<int> atom_ids);
      void SetValue(double Value);

      int  GetConstraintType() const;
      double GetConstraintValue() const;
      int GetConstraintAtomA() const;
      int GetConstraintAtomB() const;
      int GetConstraintAtomC() const;
      int GetConstraintAtomD() const;

      QJsonObject toJson();

      int ConstraintType;
      int AtomIdA;
      int AtomIdB;
      int AtomIdC;
      int AtomIdD;
      double ConstraintValue;
    };    
  }
}
