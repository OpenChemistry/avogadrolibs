// Copyright 2017-2021 Global Phasing Ltd.
//
// Modify various properties of the model.

// For modifications that depend on entities or connectivity see polyheur.hpp.

#ifndef GEMMI_MODIFY_HPP_
#define GEMMI_MODIFY_HPP_

#include "model.hpp"
#include "util.hpp"      // for vector_remove_if
#include <set>

namespace gemmi {

/// Remove alternative conformations.
/// Recursively removes all alternative conformations, keeping only the first
/// (altloc='A' or blank). For Chain level, keeps one representative per residue seqid.
/// For Residue level, removes duplicate atoms by name.
/// @tparam T Model, Chain, or Residue
template<class T> void remove_alternative_conformations(T& obj) {
  for (auto& child : obj.children())
    remove_alternative_conformations(child);
}
template<> inline void remove_alternative_conformations(Chain& chain) {
  std::set<SeqId> seqids;
  for (size_t i = 0; i < chain.residues.size(); ) {
    if (seqids.insert(chain.residues[i].seqid).second)
      ++i;
    else
      chain.residues.erase(chain.residues.begin() + i);
  }
  for (Residue& residue : chain.residues) {
    std::set<std::string> names;
    for (size_t i = 0; i < residue.atoms.size(); ) {
      Atom& atom = residue.atoms[i];
      atom.altloc = '\0';
      if (names.insert(atom.name).second)
        ++i;
      else
        residue.atoms.erase(residue.atoms.begin() + i);
    }
  }
}

/// Remove hydrogens and deuterium atoms.
/// Recursively removes all H and D atoms from the structure.
/// @tparam T Model, Chain, or Residue
template<class T> void remove_hydrogens(T& obj) {
  for (auto& child : obj.children())
    remove_hydrogens(child);
}
template<> inline void remove_hydrogens(Residue& res) {
  vector_remove_if(res.atoms, [](const Atom& a) {
    return a.element == El::H || a.element == El::D;
  });
}

/// Set isotropic ADP to the range (b_min, b_max). Values smaller than
/// b_min are changed to b_min, values larger than b_max to b_max.
/// Anisotropic ADP is left unchanged.
/// @tparam T Model, Chain, Residue, or Atom
/// @param obj object to modify
/// @param b_min minimum B-factor value
/// @param b_max maximum B-factor value
template<class T> void assign_b_iso(T& obj, float b_min, float b_max) {
  for (auto& child : obj.children())
    assign_b_iso(child, b_min, b_max);
}
template<> inline void assign_b_iso(Atom& atom, float b_min, float b_max) {
  atom.b_iso = clamp(atom.b_iso, b_min, b_max);
}

/// Remove anisotropic displacement parameters.
/// Recursively zeroes all anisotropic ADP tensors (u11, u22, u33, u12, u13, u23).
/// @tparam T Model, Chain, Residue, or Atom
template<class T> void remove_anisou(T& obj) {
  for (auto& child : obj.children())
    remove_anisou(child);
}
template<> inline void remove_anisou(Atom& atom) {
  atom.aniso = {0, 0, 0, 0, 0, 0};
}

/// Set absent ANISOU records to isotropic values derived from B_iso.
/// For atoms without anisotropic ADP, creates isotropic tensor U = B_iso/(8π²).
/// @tparam T Model, Chain, Residue, or Atom
template<class T> void ensure_anisou(T& obj) {
  for (auto& child : obj.children())
    ensure_anisou(child);
}
template<> inline void ensure_anisou(Atom& atom) {
  if (!atom.aniso.nonzero()) {
    float u = float(1. / gemmi::u_to_b() * atom.b_iso);
    atom.aniso = {u, u, u, 0.f, 0.f, 0.f};
  }
}

/// Apply a Transform to atomic positions and anisotropic displacement parameters.
/// Recursively applies the given transformation to all atom coordinates and
/// congruence-transforms anisotropic ADPs.
/// @tparam T Model, Chain, Residue, or Atom
/// @param obj object to transform
/// @param tr transformation to apply
template<class T> void transform_pos_and_adp(T& obj, const Transform& tr) {
  for (auto& child : obj.children())
    transform_pos_and_adp(child, tr);
}
template<> inline void transform_pos_and_adp(Atom& atom, const Transform& tr) {
  atom.pos = Position(tr.apply(atom.pos));
  if (atom.aniso.nonzero())
    atom.aniso = atom.aniso.transformed_by<float>(tr.mat);
}

/// Assign atom site serial numbers (1, 2, 3, ...) sequentially.
/// Optionally leaves gaps at chain ends for TER records if numbering polymer chains.
/// @param model model containing chains
/// @param numbered_ter if true, increment serial after last polymer residue in each chain
inline void assign_serial_numbers(Model& model, bool numbered_ter=false) {
  int serial = 0;
  for (Chain& chain : model.chains)
    for (Residue& res : chain.residues) {
      for (Atom& atom : res.atoms)
        atom.serial = ++serial;
      if (numbered_ter && res.entity_type == EntityType::Polymer &&
          (&res == &chain.residues.back() || (&res + 1)->entity_type != EntityType::Polymer))
        ++serial;
    }
}

/// Assign atom site serial numbers to all models in a structure.
/// @param st structure containing models
/// @param numbered_ter if true, increment serial after last polymer residue in each chain
inline void assign_serial_numbers(Structure& st, bool numbered_ter=false) {
  for (Model& model : st.models)
    assign_serial_numbers(model, numbered_ter);
}


/// Apply a function to all AtomAddress references in structure metadata.
/// Processes atom addresses in Connection, CisPep, StructSite, Helix, and Sheet records.
/// Does not update ModRes, Entity::DbRef, Entity::full_sequence, or TlsGroup::Selection.
/// @tparam Func callable taking an AtomAddress& parameter
/// @param st structure whose metadata will be processed
/// @param func function to apply to each AtomAddress
template<typename Func>
void process_addresses(Structure& st, Func func) {
  for (Connection& con : st.connections) {
    func(con.partner1);
    func(con.partner2);
  }
  for (CisPep& cispep : st.cispeps) {
    func(cispep.partner_c);
    func(cispep.partner_n);
  }
  for (StructSite& site : st.sites) {
    func(site.residue);
    for (StructSite::Member& member : site.members)
      func(member.auth);
  }
  for (Helix& helix : st.helices) {
    func(helix.start);
    func(helix.end);
  }
  for (Sheet& sheet : st.sheets)
    for (Sheet::Strand& strand : sheet.strands) {
      func(strand.start);
      func(strand.end);
      func(strand.hbond_atom2);
      func(strand.hbond_atom1);
    }
}

/// Apply a function to all SeqId references in structure metadata.
/// Processes sequence IDs in Connection/CisPep/StructSite/Helix/Sheet records,
/// ModRes entries, and TlsGroup selections.
/// Does not process Entity::DbRef::seq_begin/seq_end (no single chain name).
/// @tparam Func callable taking (const std::string& chain_name, SeqId& seqid)
/// @param st structure whose metadata will be processed
/// @param func function to apply to each (chain_name, seqid) pair
template<typename Func>
void process_sequence_ids(Structure& st, Func func) {
  process_addresses(st, [&](AtomAddress& aa) { func(aa.chain_name, aa.res_id.seqid); });
  for (ModRes& modres : st.mod_residues)
    func(modres.chain_name, modres.res_id.seqid);
  for (RefinementInfo& ri : st.meta.refinement)
    for (TlsGroup& tls : ri.tls_groups)
      for (TlsGroup::Selection& sel : tls.selections) {
        func(sel.chain, sel.res_begin);
        func(sel.chain, sel.res_end);
      }
}

/// Rename a chain throughout the structure.
/// Updates all occurrences of old_name to new_name in models and metadata.
/// @param st structure to modify
/// @param old_name current chain name
/// @param new_name new chain name
inline void rename_chain(Structure& st, const std::string& old_name,
                                        const std::string& new_name) {
  auto update = [&](std::string& name) {
    if (name == old_name)
      name = new_name;
  };
  process_addresses(st, [&](AtomAddress& aa) { update(aa.chain_name); });
  for (ModRes& modres : st.mod_residues)
    update(modres.chain_name);
  for (RefinementInfo& ri : st.meta.refinement)
    for (TlsGroup& tls : ri.tls_groups)
      for (TlsGroup::Selection& sel : tls.selections)
        update(sel.chain);
  for (Model& model : st.models)
    for (Chain& chain : model.chains)
      update(chain.name);
}

/// Rename residues throughout the structure.
/// Updates all residues named old_name to new_name in models and metadata.
/// Also updates Entity sequences and StructSite member records.
/// @param st structure to modify
/// @param old_name current residue name
/// @param new_name new residue name
inline void rename_residues(Structure& st, const std::string& old_name,
                                           const std::string& new_name) {
  auto update = [&](ResidueId& rid) {
    if (rid.name == old_name)
      rid.name = new_name;
  };
  process_addresses(st, [&](AtomAddress& aa) { update(aa.res_id); });
  for (StructSite& site : st.sites)
    for (StructSite::Member& member : site.members)
      if (member.label_comp_id == old_name)
        member.label_comp_id = new_name;
  for (ModRes& modres : st.mod_residues)
    update(modres.res_id);
  for (Entity& ent : st.entities)
    for (std::string& mon_ids : ent.full_sequence)
      for (size_t start = 0;;) {
        size_t end = mon_ids.find(',', start);
        if (mon_ids.compare(start, end-start, old_name) == 0) {
          mon_ids.replace(start, end-start, new_name);
          if (end != std::string::npos)
            end = start + new_name.size();
        }
        if (end == std::string::npos)
          break;
        start = end + 1;
      }
  for (Model& model : st.models)
    for (Chain& chain : model.chains)
      for (Residue& res : chain.residues)
        update(res);
}


/// Rename atoms in residues of a specific type.
/// For residues named res_name, renames atoms according to the old→new map.
/// Updates both atomic coordinates and metadata references.
/// @param st structure to modify
/// @param res_name residue type to target
/// @param old_new map from old atom names to new atom names
inline void rename_atom_names(Structure& st, const std::string& res_name,
                              const std::map<std::string, std::string>& old_new) {
  auto update = [&old_new](std::string& name) {
    auto it = old_new.find(name);
    if (it != old_new.end())
      name = it->second;
  };
  process_addresses(st, [&](AtomAddress& aa) {
      if (aa.res_id.name == res_name)
        update(aa.atom_name);
  });
  for (Model& model : st.models)
    for (Chain& chain : model.chains)
      for (Residue& res : chain.residues)
        if (res.name == res_name) {
          for (Atom& atom : res.atoms)
            update(atom.name);
        }
}


/// Expand deuterium-fraction representation into explicit H/D alternate conformations.
/// Converts H atoms with non-zero d_fraction into H/D altloc pairs.
/// If d_fraction >= 1, converts to pure D; otherwise creates H altloc 'A' and D altloc 'D'.
/// @param res residue containing hydrogens to expand
inline void replace_d_fraction_with_altlocs(Residue& res) {
  for (size_t i = res.atoms.size(); i-- != 0; ) {
    Atom& atom = res.atoms[i];
    float d_fraction = atom.fraction;
    if (atom.element == El::H && d_fraction > 0) {
      if (d_fraction >= 1) {
        atom.element = El::D;
        if (atom.name[0] == 'H')
          atom.name[0] = 'D';
      } else {
        int alt_offset = atom.altloc;
        if (alt_offset) {
          alt_offset -= 'A';
          // we don't expect 4+ altlocs - ignore such cases
          if (alt_offset < 0 || alt_offset >= 3)
            continue;
        }
        atom.altloc = 'A' + alt_offset;
        float d_occ = atom.occ * d_fraction;
        atom.occ *= (1 - d_fraction);
        auto deut = res.atoms.insert(res.atoms.begin() + i + 1, atom);
        deut->altloc = 'D' + alt_offset;
        deut->element = El::D;
        deut->occ = d_occ;
        if (deut->name[0] == 'H')
          deut->name[0] = 'D';
      }
    }
  }
}

/// Contract explicit D atoms into H atoms with fractional occupancy.
/// Merges H and D atoms at the same position into a single H atom,
/// storing the D occupancy as the fraction field.
/// @param res residue containing deuterium atoms to contract
/// @return true if any D atoms were found and processed, false otherwise
inline bool replace_deuterium_with_fraction(Residue& res) {
  bool found = false;
  for (auto d = res.atoms.end(); d-- != res.atoms.begin(); )
    if (d->element == El::D) {
      found = true;
      auto h = res.atoms.begin();
      for (; h != res.atoms.end(); ++h)
        if (h->element == El::H && h->pos.approx(d->pos, 1e-9))
          break;
      if (h != res.atoms.end()) {
        h->occ += d->occ;
        h->fraction = h->occ > 0.f ? d->occ / h->occ : 0.f;
        if (h->altloc) {
          bool keep_altloc = false;
          for (auto i = res.atoms.begin(); i != res.atoms.end(); ++i)
            if (i != d && i != h && (i->name == h->name || i->name == d->name))
              keep_altloc = true;
          if (!keep_altloc)
            h->altloc = '\0';
        }
        res.atoms.erase(d);
      } else {
        d->element = El::H;
        d->fraction = 1;
        // Atom name is left unchanged. prepare_topology() first calls this
        // function and then conditionally changes the name (Dxx -> Hxx).
      }
    }
  return found;
}

/// Toggle deuterium representation between fraction and explicit altlocs.
/// Hydrogens modelled as H/D mixtures can be stored either as:
/// - Two atoms with altlocs H and D (same position/ADP, different occupancies)
/// - Single H atom with ccp4_deuterium_fraction parameter (CCP4/Refmac extension)
/// This function converts between the two representations.
/// @param st structure to modify
/// @param store_fraction if true, use fraction representation; otherwise use altlocs
inline void store_deuterium_as_fraction(Structure& st, bool store_fraction) {
  if (st.has_d_fraction == store_fraction)
    return;
  st.has_d_fraction = false;
  for (Model& model : st.models)
    for (Chain& chain : model.chains)
      for (Residue& res : chain.residues)
        if (store_fraction) {
          if (replace_deuterium_with_fraction(res))
            st.has_d_fraction = true;
        } else {
          replace_d_fraction_with_altlocs(res);
        }
}

/// Set the deuterium fraction of all hydrogen atoms.
/// Assigns the fraction field of all H atoms in the structure to d_fract.
/// @param st structure to modify
/// @param d_fract deuterium fraction to assign (0.0 to 1.0)
inline void set_deuterium_fraction_of_hydrogens(Structure& st, float d_fract) {
  st.has_d_fraction = true;
  for (Model& model : st.models)
    for (Chain& chain : model.chains)
      for (Residue& res : chain.residues)
        for (Atom& atom : res.atoms)
          if (atom.is_hydrogen())
            atom.fraction = d_fract;
}

/// Transform structure to the standard crystallographic frame.
/// Converts to standard coordinates where the a-axis is along x,
/// the b-axis is in the xy-plane, and c-axis points along +z.
/// Updates ORIGX matrices and NCS operators accordingly.
/// Only operates on crystal structures with explicit transformation matrices.
/// @param st structure to transform
inline void standardize_crystal_frame(Structure& st) {
  if (!st.cell.explicit_matrices || !st.cell.is_crystal())
    return;
  Transform orig_frac = st.cell.frac;
  st.cell.explicit_matrices = false;
  st.cell.calculate_properties();
  Transform tr = st.cell.orth.combine(orig_frac);
  Transform tr_inv = tr.inverse();
  st.has_origx = true;
  st.origx = tr_inv.combine(st.origx);
  for (NcsOp& ncsop : st.ncs)
    ncsop.tr = tr.combine(ncsop.tr).combine(tr_inv);
  transform_pos_and_adp(st, tr);
}

} // namespace gemmi
#endif
