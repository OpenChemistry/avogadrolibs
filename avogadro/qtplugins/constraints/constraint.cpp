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

      switch (ConstraintType)
        {
        case 0 ... 4:
          //          AtomA = &(c_model->c_molecule->atom(a));
          Atoms << c_model->c_molecule->atom(a);
          break;

        case 5:
          // AtomA =
          Atoms << c_model->c_molecule->atom(a);
          //AtomB =
          Atoms << c_model->c_molecule->atom(b);
          break;

        case 6:
          //AtomA =
          Atoms << c_model->c_molecule->atom(a);
          //AtomB =
          Atoms << c_model->c_molecule->atom(b);
          //AtomC =
          Atoms << c_model->c_molecule->atom(c);
          break;

        case 7:
          //AtomA =
          Atoms << c_model->c_molecule->atom(a);
          //AtomB =
          Atoms << c_model->c_molecule->atom(b);
          //AtomC =
          Atoms << c_model->c_molecule->atom(c);
          //AtomD =
          Atoms << c_model->c_molecule->atom(d);
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

    const Core::Atom* Constraint::GetConstraintAtomA() const
    {
      if (Atoms.size() >= 1)
        {
          const Core::Atom* a;
          a = &Atoms[0];
          return  a;
        }
      else
        {
          return nullptr;
        }
    }

    const Core::Atom* Constraint::GetConstraintAtomB() const
    {
      if (Atoms.size() >= 2)
        {
          return &Atoms[1];
        }
      else
        {
          return nullptr;
        }
    }

    const Core::Atom* Constraint::GetConstraintAtomC() const
    {
      if (Atoms.size() >= 3)
        {
          return &Atoms[2];
        }
      else
        {
          return nullptr;
        }
    }

    const Core::Atom* Constraint::GetConstraintAtomD() const
    {
      if (Atoms.size() >= 4)
        {
          return &Atoms[3];
        }
      else
        {
          return nullptr;
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
          ConstraintAtoms << static_cast<int>(GetConstraintAtomA()->index());
          break;
        case 5:
          ConstraintAtoms << static_cast<int>(GetConstraintAtomA()->index())
                          << static_cast<int>(GetConstraintAtomB()->index());
          break;
        case 6:
          ConstraintAtoms << static_cast<int>(GetConstraintAtomA()->index())
                          << static_cast<int>(GetConstraintAtomB()->index())
                          << static_cast<int>(GetConstraintAtomC()->index());
          break;
        case 7:
          ConstraintAtoms << static_cast<int>(GetConstraintAtomA()->index())
                          << static_cast<int>(GetConstraintAtomB()->index())
                          << static_cast<int>(GetConstraintAtomC()->index())
                          << static_cast<int>(GetConstraintAtomD()->index());
          break;
        }

      ConstraintJ.insert("atoms", ConstraintAtoms);

      return ConstraintJ;
    }
  } //namespace QtPlugins
}  //namespace Avogadroe
