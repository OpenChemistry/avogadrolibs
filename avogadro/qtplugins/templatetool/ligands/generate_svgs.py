#!/usr/bin/env python3
import os, sys, re
from rdkit import Chem
from rdkit.Chem.Draw import rdMolDraw2D

def mol_to_svg(mol, size=(256,256)):
    drawer = rdMolDraw2D.MolDraw2DSVG(*size)
    rdMolDraw2D.PrepareAndDrawMolecule(drawer, mol)
    drawer.FinishDrawing()
    return drawer.GetDrawingText()

def safe_mol_from_smiles(smi):
    """
    Try parsing & sanitizing; on failure, fall back to:
      1) no-sanitize
      2) stripping [H] and re-parsing
    """
    # 1) Try normal
    mol = Chem.MolFromSmiles(smi)
    if mol:
        try:
            Chem.SanitizeMol(mol)
            return mol
        except Exception:
            pass

    # 2) Try sanitize=False + best-effort sanitize
    mol = Chem.MolFromSmiles(smi, sanitize=False)
    if mol:
        try:
            # skip properties (which includes valence checks)
            flags = Chem.SANITIZE_ALL ^ Chem.SANITIZE_PROPERTIES
            Chem.SanitizeMol(mol, flags)
            return mol
        except Exception:
            pass

    # 3) Strip explicit H’s and re-try
    stripped = re.sub(r'\[H\]', '', smi)
    if stripped != smi:
        mol = Chem.MolFromSmiles(stripped)
        if mol:
            try:
                Chem.SanitizeMol(mol)
            except Exception:
                pass
            return mol

    # give up
    return None

def batch_generate(input_dir):
    svg_dir = os.path.join(input_dir, 'svgs')
    os.makedirs(svg_dir, exist_ok=True)

    for fname in os.listdir(input_dir):
        if not fname.lower().endswith('.smi'):
            continue

        base = os.path.splitext(fname)[0]
        smi_path = os.path.join(input_dir, fname)
        # grab first non-blank, non-# line
        with open(smi_path) as f:
            lines = [l.strip() for l in f]
        line = next((L for L in lines if L and not L.startswith('#')), None)
        if not line:
            print(f"⚠️  no SMILES in {fname}")
            continue

        smiles = line.split()[0]
        mol = safe_mol_from_smiles(smiles)
        if not mol:
            print(f"⚠️  couldn’t parse SMILES in {fname}: {smiles}")
            continue

        svg = mol_to_svg(mol)
        out_path = os.path.join(svg_dir, f"{base}.svg")
        with open(out_path, 'w') as out:
            out.write(svg)
        print(f"✓ {base}.svg")

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else '.'
    batch_generate(target)
