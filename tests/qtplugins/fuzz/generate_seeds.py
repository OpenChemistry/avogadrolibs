#!/usr/bin/env python3
"""Write the seed corpus for fuzz_qtplugin_commands.

The byte format is documented at the top of fuzz-qtplugin-commands.cpp.
Usage: generate_seeds.py [output directory]
(default: qtplugin_commands/ next to this script). Commands are chosen by
name (kind 10), so the seeds do not depend on the registration order.
"""
import os
import struct
import sys

KEYS = ["atoms", "id", "index", "element", "axis", "value", "tolerance",
        "atom", "indices", "resolution", "position", "bondTo", "bondOrder",
        "order", "mode"]


def u8(v):
    return struct.pack("<B", v)


def string(s):
    b = s.encode()[:16]
    return u8(len(b)) + b


# Values: (type byte, payload)
def i32(v):
    return u8(0) + struct.pack("<i", v)


def small(v):  # stored as v + 3
    return u8(1) + u8(v + 3)


def i64(v):
    return u8(2) + struct.pack("<q", v)


def f64(v):
    return u8(3) + struct.pack("<d", v)


def special_double(i):  # 0 NaN 1 inf 2 -inf 3 0 4 -0 5 max 6 -max 7 denorm
    return u8(4) + u8(i)


def text(s):
    return u8(5) + string(s)


def boolean(b):
    return u8(6) + u8(1 if b else 0)


def null():
    return u8(7)


def special_int(i):
    return u8(10) + u8(i)


def lst(*scalars):  # scalars are (type, payload) with the type < 11
    out = u8(11) + u8(len(scalars))
    for s in scalars:
        out += s
    return out


def options(**kw):
    out = u8(len(kw))
    for k, v in kw.items():
        out += u8(KEYS.index(k)) + v
    return out


def raw_options(pairs):
    out = u8(len(pairs))
    for k, v in pairs:
        out += (u8(KEYS.index(k)) if k in KEYS else u8(200) + string(k)) + v
    return out


def command(name, opts=None):
    return u8(10) + string(name) + (opts if opts is not None else u8(0))


UNDO, REDO, UNDO_REDO, TOGGLE = u8(12), u8(13), u8(14), u8(15)


def seed(shape, ops, constraints=False, order2=False, selection=0):
    spec = shape | (4 if constraints else 0) | (8 if order2 else 0)
    return u8(spec) + u8(selection) + u8(len(ops) - 1) + b"".join(ops)


def ix(*ids):  # a list of small ints, as the atoms option wants
    return lst(*[small(i) for i in ids])


SEEDS = {
    "select_element_layer_undo": seed(0, [
        command("selectElement", options(element=text("O"))),
        command("createLayerFromSelection"), UNDO, REDO]),
    "select_all_invert_twice": seed(0, [
        command("selectAll"), command("invertSelection"),
        command("invertSelection"), command("enlargeSelection"),
        command("shrinkSelection"), UNDO_REDO]),
    "select_element_number": seed(0, [
        command("selectElement", options(element=small(5)))]),
    "select_element_bad": seed(0, [
        command("selectElement", options(element=text("Zz"))),
        command("selectElement", options(element=special_int(3))),
        command("selectElement", options(element=null())),
        command("selectElement")]),
    "measure_distance_edit_undo": seed(1, [
        command("measureDistance", options(atoms=ix(0, 1))),
        command("editDistance", options(atoms=ix(1, 2), value=f64(1.2))),
        UNDO, REDO]),
    "measure_angle_dihedral": seed(1, [
        command("editAngle", options(atoms=ix(0, 1, 2), value=f64(120.0))),
        command("editDihedral", options(atoms=ix(0, 1, 2, 3),
                                        value=f64(180.0))),
        UNDO_REDO]),
    "measure_malformed": seed(0, [
        command("measureDistance", options(atoms=ix(0, 0))),
        command("measureDistance", options(atoms=ix(0, 99))),
        command("measureDistance", options(atoms=ix(-1, 2))),
        command("measureAngle", options(atoms=lst(special_double(0),
                                                  small(1), small(2)))),
        command("measureDihedral", options(atoms=ix(0, 1, 2))),
        command("editDistance", options(atoms=ix(0, 1),
                                        value=special_double(0))),
        command("editDihedral", options(atoms=ix(0, 1, 2, 3),
                                        value=special_double(1))),
        command("editAngle", options(atoms=ix(0, 1, 2),
                                     value=special_double(5))),
        command("editDistance", options(atoms=text("0 1"), value=small(1)))]),
    "bonding_cycle": seed(0, [
        command("removeBonds"), command("createBonds"),
        command("addBondOrders"), UNDO, UNDO, REDO], order2=True),
    "bonding_with_selection": seed(0, [
        command("removeBonds"), command("createBonds"),
        command("addBondOrders")], selection=0b000011),
    "align_center_and_align": seed(1, [
        command("centerAtom", options(id=small(2))),
        command("alignAtom", options(index=small(3), axis=text("x"))),
        command("alignAtom", options(index=small(0), axis=small(2))),
        UNDO_REDO]),
    "align_malformed": seed(1, [
        command("centerAtom", options(id=special_int(5))),
        command("centerAtom", options(id=text("abc"))),
        command("centerAtom", options(id=special_double(0))),
        command("centerAtom"),
        command("alignAtom", options(index=small(1), axis=text("w"))),
        command("alignAtom", options(index=small(1), axis=special_int(8))),
        command("alignAtom", options(id=small(1))),
        command("alignAtom", options(id=small(-1), axis=small(0)))]),
    "crystal_wrap_orient": seed(2, [
        command("wrapUnitCell"), command("wrapUnitCell"),
        command("standardCrystalOrientation"), UNDO, UNDO, REDO]),
    "crystal_triclinic": seed(3, [
        command("standardCrystalOrientation"), command("wrapUnitCell"),
        UNDO_REDO, command("alignAtom", options(id=small(1),
                                                axis=text("y")))]),
    "crystal_no_cell": seed(0, [
        command("wrapUnitCell"), command("standardCrystalOrientation")]),
    "focus_selection": seed(0, [
        command("focusSelection"), command("unfocus"),
        command("selectElement", options(element=text("C"))),
        command("focusSelection"), command("unfocus")], selection=0b101),
    "detach_and_reattach": seed(0, [
        TOGGLE, command("selectAll"), command("createBonds"),
        command("editDistance", options(atoms=ix(0, 1), value=f64(1.0))),
        TOGGLE, command("selectAll"), UNDO_REDO]),
    "unknown_commands": seed(0, [
        command("noSuchCommand"), command(""),
        command("selectall", options(atoms=ix(0, 1))),
        command("renderVDW", options(resolution=f64(0.001)))]),
    "constraints_and_edits": seed(0, [
        command("editDistance", options(atoms=ix(0, 1), value=f64(2.0))),
        command("editAngle", options(atoms=ix(1, 0, 2), value=f64(90.0))),
        command("createLayerFromSelection"), UNDO, UNDO, UNDO, REDO],
        constraints=True, selection=0b110),
    "huge_and_negative_indices": seed(1, [
        command("measureDistance", options(atoms=lst(special_int(8),
                                                     special_int(9)))),
        command("centerAtom", options(id=i64(-(2 ** 63)))),
        command("centerAtom", options(id=i32(2 ** 31 - 1))),
        command("alignAtom", options(id=i64(2 ** 40), axis=text("z"))),
        command("measureAngle", options(atoms=lst(special_int(3),
                                                  special_int(4),
                                                  special_int(0))))]),
    "nested_and_wrong_types": seed(0, [
        command("selectElement", options(element=lst(small(1), small(1)))),
        command("measureDistance", options(atoms=boolean(True))),
        command("centerAtom", options(id=boolean(True), index=null())),
        command("editDistance", options(atoms=ix(0, 1), value=text("1.5"))),
        command("alignAtom", options(axis=lst(small(0)), id=small(0)))]),
    "select_atoms_modes": seed(0, [
        command("selectAtoms", options(indices=ix(0, 1))),
        command("selectAtoms", options(indices=ix(2), mode=text("add"))),
        command("selectAtoms", options(indices=ix(0), mode=text("remove"))),
        command("selectAtoms", options(indices=ix(0, 99))),
        command("selectAtoms", options(indices=lst(special_double(0)),
                                       mode=small(1))),
        UNDO_REDO]),
    "editor_add_remove": seed(1, [
        command("addAtom", options(element=text("C"),
                                   position=lst(f64(1.0), f64(2.0),
                                                f64(3.0)),
                                   bondTo=small(0), bondOrder=small(2))),
        command("addBond", options(atoms=ix(0, 3), order=small(1))),
        command("removeBond", options(atoms=ix(0, 3))),
        command("removeSelectedAtoms"), UNDO, REDO]),
    "editor_malformed": seed(0, [
        command("addAtom", options(element=text("C"),
                                   position=lst(special_double(0), small(0),
                                                small(0)))),
        command("addAtom", options(element=small(6),
                                   position=lst(special_double(1), small(0),
                                                small(0)))),
        command("addAtom", options(element=text("C"))),
        command("addBond", options(atoms=ix(0, 0))),
        command("addBond", options(atoms=ix(0, 99), order=small(7))),
        command("removeBond", options(atoms=ix(-1, 2))),
        command("removeBond", options(atoms=boolean(True)))]),
}


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        here, "qtplugin_commands")
    os.makedirs(out, exist_ok=True)
    for name, data in SEEDS.items():
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
    print("wrote %d seeds to %s" % (len(SEEDS), out))


if __name__ == "__main__":
    main()
