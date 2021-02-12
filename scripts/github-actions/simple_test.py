import avogadro

ethane_xyz = '''8
Ethane
H      1.18508   -0.00384    0.98752
C      0.75162   -0.02244   -0.02084
H      1.16693    0.83301   -0.56931
H      1.11552   -0.93289   -0.51453
C     -0.75159    0.02250    0.02089
H     -1.16688   -0.83337    0.56870
H     -1.11569    0.93261    0.51508
H     -1.18499    0.00442   -0.98752
'''


def test_simple():
    mol = avogadro.core.Molecule()
    manager = avogadro.io.FileFormatManager()

    assert mol.atom_count() == 0

    assert manager.read_string(mol, ethane_xyz, 'xyz')

    assert mol.atom_count() == 8
    assert mol.mass() == 30.06904


if __name__ == '__main__':
    test_simple()
