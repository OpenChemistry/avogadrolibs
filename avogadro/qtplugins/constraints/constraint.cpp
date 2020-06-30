#include "constraint.h"

namespace Avogadro {
  namespace QtPlugins {
    Constraint::Constraint(int type, int a, int b, int c, int d, double value)
    {
      ConstraintType = type;
      AtomIdA = a;
      AtomIdB = b;
      AtomIdC = c;
      AtomIdD = d;
      ConstraintValue = value;
    }
    Constraint::~Constraint(){}
    void Constraint::SetConstraintType(int type)
    {
      ConstraintType = type;
    }
    void Constraint::SetValue(double Value)
    {
      ConstraintValue = Value;
    }
    int Constraint::GetConstraintType() const
    {
      return ConstraintType;
    }
    double Constraint::GetConstraintValue() const
    {
      return ConstraintValue;
    }
    int Constraint::GetConstraintAtomA() const
    {
      return AtomIdA;
    }
    int Constraint::GetConstraintAtomB() const
    {
      return AtomIdB;
    }
    int Constraint::GetConstraintAtomC() const
    {
      return AtomIdC;
    }
    int Constraint::GetConstraintAtomD() const
    {
      return AtomIdD;
    }
  }
}
