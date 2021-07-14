#include "constraint.h"

namespace Avogadro {
  namespace QtPlugins {

    Constraint::Constraint(int type,
                           int a,
                           int b,
                           int c,
                           int d,
                           double value,
                           ConstraintsModel* model)
    {
      c_model = model;
      ConstraintType = type;

      //adjusting for 0 indexing
      a = a-1;
      b = b-1;
      c = c-1;
      d = d-1;

      // store unique AtomIds

      switch (ConstraintType)
        {
        case 0 ... 4:
          // AtomA
          Atoms << c_model->c_molecule->atomUniqueId(a);
          break;

        case 5:
          //AtomA
          Atoms << c_model->c_molecule->atomUniqueId(a);
          //AtomB
          Atoms << c_model->c_molecule->atomUniqueId(b);
          break;

        case 6:
          //AtomA
          Atoms << c_model->c_molecule->atomUniqueId(a);
          //AtomB
          Atoms << c_model->c_molecule->atomUniqueId(b);
          //AtomC
          Atoms << c_model->c_molecule->atomUniqueId(c);
          break;

        case 7:
          //AtomA
          Atoms << c_model->c_molecule->atomUniqueId(a);
          //AtomB
          Atoms << c_model->c_molecule->atomUniqueId(b);
          //AtomC
          Atoms << c_model->c_molecule->atomUniqueId(c);
          //AtomD
          Atoms << c_model->c_molecule->atomUniqueId(d);
        }

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

    const Index Constraint::GetConstraintAtomA() const
    {
      if (Atoms.size() >= 1) //returned for all constraint types
        {
          return c_model->c_molecule->atomByUniqueId(Atoms[0]).index()+1;
        }
      else
        {
          return 0;
        }
    }

    const Index Constraint::GetConstraintAtomB() const
    {
      if (Atoms.size() >= 2) //distance, angle and torsion constraints
        {
          return c_model->c_molecule->atomByUniqueId(Atoms[1]).index()+1;
        }
      else
        {
          return 0;
        }
    }

    const Index Constraint::GetConstraintAtomC() const
    {
      if (Atoms.size() >= 3) //angle and torsion constraints
        {
          return c_model->c_molecule->atomByUniqueId(Atoms[2]).index()+1;
        }
      else
        {
          return 0;
        }
    }

    const Index Constraint::GetConstraintAtomD() const
    {
      if (Atoms.size() >= 4) //torsion constraints only
        {
          return c_model->c_molecule->atomByUniqueId(Atoms[3]).index()+1;
        }
      else
        {
          return 0;
        }
    }

    QJsonObject Constraint::toJson()
    {
      QJsonObject ConstraintJ;
      ConstraintJ["type"] = GetConstraintType();
      ConstraintJ["value"] = GetConstraintValue();

      QJsonArray ConstraintAtoms;

      switch (GetConstraintType())
        {
        case 0 ... 4:
          ConstraintAtoms << static_cast<int>(GetConstraintAtomA());
          break;
        case 5:
          ConstraintAtoms << static_cast<int>(GetConstraintAtomA())
                          << static_cast<int>(GetConstraintAtomB());
          break;
        case 6:
          ConstraintAtoms << static_cast<int>(GetConstraintAtomA())
                          << static_cast<int>(GetConstraintAtomB())
                          << static_cast<int>(GetConstraintAtomC());
          break;
        case 7:
          ConstraintAtoms << static_cast<int>(GetConstraintAtomA())
                          << static_cast<int>(GetConstraintAtomB())
                          << static_cast<int>(GetConstraintAtomC())
                          << static_cast<int>(GetConstraintAtomD());
          break;
        }

      ConstraintJ.insert("atoms", ConstraintAtoms);

      return ConstraintJ;
    }
  } //namespace QtPlugins
}  //namespace Avogadro
