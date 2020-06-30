#include <QtCore>

namespace Avogadro {
  namespace QtPlugins {
    class Constraint
    {
    public:
      explicit Constraint(int ConstraintType, int AtomIdA, int AtomIdB, int AtomIdC, int AtomIdD, double ConstraintValue);
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

      int ConstraintType;
      int AtomIdA;
      int AtomIdB;
      int AtomIdC;
      int AtomIdD;
      float ConstraintValue;
    };    
  }
}
