import sys
import json
from rdkit import Chem

def load_cjson(path):
    # 1) Read JSON
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 2) Create editable mol
    rw = Chem.RWMol()

    # 3) Add atoms
    numbers = (
        data
        .get('atoms', {})
        .get('elements', {})
        .get('number', [])
    )
    for z in numbers:
        rw.AddAtom(Chem.Atom(int(z)))

    # 4) Add bonds
    bonds = data.get('bonds', {}).get('connections', {})
    idxs = bonds.get('index', [])
    orders = bonds.get('order', [])

    # Normalize flat [0,1, 1,2, ...] → [(0,1),(1,2),...]
    if idxs and isinstance(idxs[0], int):
        pairs = list(zip(idxs[0::2], idxs[1::2]))
    else:
        pairs = idxs  # already a list of [i,j] pairs

    for idx, (i, j) in enumerate(pairs):
        order = orders[idx] if idx < len(orders) else 1
        bt = {
            1: Chem.BondType.SINGLE,
            2: Chem.BondType.DOUBLE,
            3: Chem.BondType.TRIPLE
        }.get(order, Chem.BondType.SINGLE)
        rw.AddBond(int(i), int(j), bt)

    return rw.GetMol()

def main():
    if len(sys.argv) != 2:
        print("Usage: read_cjson.py file.cjson", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]
    try:
        mol = load_cjson(path)
        smiles = Chem.MolToSmiles(mol)
        print(smiles)
    except Exception as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
