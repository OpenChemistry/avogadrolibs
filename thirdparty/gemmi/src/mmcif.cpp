// Copyright 2017-2023 Global Phasing Ltd.

#include <gemmi/mmcif.hpp>   // for string_to_int
#include <array>
#include <cmath>             // for NAN
#include <unordered_map>
#include <gemmi/mmcif_impl.hpp> // for set_cell_from_mmcif
#include <gemmi/atox.hpp>    // for string_to_int
#include <gemmi/enumstr.hpp> // for entity_type_from_string, polymer_type_from_string
#include <gemmi/numb.hpp>    // for as_number
#include <gemmi/polyheur.hpp>  // for restore_full_ccd_codes

namespace gemmi {

namespace {

void copy_int(const cif::Table::Row& row, int n, int& dest) {
  if (row.has2(n))
    dest = cif::as_int(row[n]);
}
void copy_double(const cif::Table::Row& row, int n, double& dest) {
  if (row.has2(n))
    dest = cif::as_number(row[n]);
}
void copy_string(const cif::Table::Row& row, int n, std::string& dest) {
  if (row.has2(n))
    dest = cif::as_string(row[n]);
}

template<typename T>
SMat33<T> get_smat33(cif::Table::Row& row, int n) {
  return SMat33<T>{(T) cif::as_number(row[n+0]),
                   (T) cif::as_number(row[n+1]),
                   (T) cif::as_number(row[n+2]),
                   (T) cif::as_number(row[n+3]),
                   (T) cif::as_number(row[n+4]),
                   (T) cif::as_number(row[n+5])};
}

std::unordered_map<std::string, SMat33<float>> get_anisotropic_u(cif::Block& block) {
  cif::Table aniso_tab = block.find("_atom_site_anisotrop.",
                                    {"id", "U[1][1]", "U[2][2]", "U[3][3]",
                                     "U[1][2]", "U[1][3]", "U[2][3]"});
  std::unordered_map<std::string, SMat33<float>> aniso_map;
  for (auto ani : aniso_tab)
    aniso_map.emplace(ani[0], get_smat33<float>(ani, 1));
  return aniso_map;
}

std::vector<std::string> transform_tags(const std::string& mstr, const std::string& vstr) {
  return {mstr + "[1][1]", mstr + "[1][2]", mstr + "[1][3]", vstr + "[1]",
          mstr + "[2][1]", mstr + "[2][2]", mstr + "[2][3]", vstr + "[2]",
          mstr + "[3][1]", mstr + "[3][2]", mstr + "[3][3]", vstr + "[3]"};
}

Transform get_transform_matrix(const cif::Table::Row& r) {
  Transform t;
  for (int i = 0; i < 3; ++i) {
    for (int j = 0; j < 3; ++j)
      t.mat[i][j] = cif::as_number(r[4*i+j]);
    t.vec.at(i) = cif::as_number(r[4*i+3]);
  }
  return t;
}

SeqId make_seqid(std::string seqid, const std::string* icode) {
  SeqId ret;
  if (icode)
    // the insertion code happens to be always a single letter
    ret.icode = cif::as_char(*icode, ' ');
  if (!seqid.empty()) {
    // old mmCIF files have auth_seq_id as number + icode (e.g. 15A)
    if (seqid.back() >= 'A') {
      if (ret.icode == ' ')
        ret.icode = seqid.back();
      else if (ret.icode != seqid.back())
        fail("Inconsistent insertion code in " + seqid);
      seqid.pop_back();
    }
    // 7pvv has an empty seqnum in tls description, don't throw
    if (!seqid.empty())
      ret.num = cif::as_int(seqid, Residue::OptionalNum::None);
  }
  return ret;
}

inline ResidueId make_resid(const std::string& name,
                            const std::string& seqid,
                            const std::string* icode) {
  return ResidueId{make_seqid(seqid, icode), {}, name};
}

void read_chemcomp_info(cif::Block& block, Structure& st) {
  for (auto row : block.find("_chem_comp.", {"id", "?type"})) {
    ChemComp& cc = st.chemcomps[row.str(0)];
    cc.name = row.str(0);
    if (row.has2(1))
      cc.type_or_group = row.str(1);
  }
  for (auto row : block.find("_chem_comp_bond.",
                             {"comp_id", "atom_id_1", "atom_id_2",
                              "?type", "?value_order",
                              "?aromatic", "?pdbx_aromatic_flag",
                              "?pdbx_stereo_config", "?pdbx_ordinal",
                              "?value_dist", "?value_dist_esd",
                              "?value_dist_nucleus", "?value_dist_nucleus_esd"})) {
    ChemComp& cc = st.chemcomps[row.str(0)];
    if (cc.name.empty())
      cc.name = row.str(0);
    std::string aromatic_flag = row.one_of(5, 6);
    std::string bond_type = row.one_of(3, 4);
    cc.rt.bonds.push_back({{1, row.str(1)}, {1, row.str(2)},
                           bond_type_from_string(bond_type),
                           !aromatic_flag.empty() &&
                             (aromatic_flag[0] | 0x20) == 'y',
                           row.has2(9) ? cif::as_number(row[9]) : NAN,
                           row.has2(10) ? cif::as_number(row[10]) : NAN,
                           row.has2(11) ? cif::as_number(row[11]) : NAN,
                           row.has2(12) ? cif::as_number(row[12]) : NAN,
                           row.has2(7) ? row.str(7) : "",
                           row.has2(8) ? cif::as_int(row[8]) : 0});
  }
}

std::vector<Helix> read_helices(cif::Block& block) {
  std::vector<Helix> helices;
  for (const auto row : block.find("_struct_conf.", {
        "conf_type_id",                                          // 0
        "beg_auth_asym_id", "beg_label_comp_id",                 // 1-2
        "beg_auth_seq_id", "?pdbx_beg_PDB_ins_code",             // 3-4
        "end_auth_asym_id", "end_label_comp_id",                 // 5-6
        "end_auth_seq_id", "?pdbx_end_PDB_ins_code",             // 7-8
        "?pdbx_PDB_helix_class", "?pdbx_PDB_helix_length"})) {   // 9-10
    if (alpha_up(row.str(0)[0]) != 'H')
      continue;
    Helix h;
    h.start.chain_name = row.str(1);
    h.start.res_id = make_resid(row.str(2), row.str(3), row.ptr_at(4));
    h.end.chain_name = row.str(5);
    h.end.res_id = make_resid(row.str(6), row.str(7), row.ptr_at(8));
    if (row.has(9))
      h.set_helix_class_as_int(cif::as_int(row[9], -1));
    if (row.has(10))
      h.length = cif::as_int(row[10], -1);
    helices.push_back(h);
  }
  return helices;
}

std::vector<Sheet> read_sheets(cif::Block& block) {
  std::vector<Sheet> sheets;
  for (const std::string& sheet_id : block.find_values("_struct_sheet.id"))
    sheets.emplace_back(sheet_id);
  for (const auto row : block.find("_struct_sheet_range.", {
        "sheet_id", "id",                                        // 0-1
        "beg_auth_asym_id", "beg_label_comp_id",                 // 2-3
        "beg_auth_seq_id", "?pdbx_beg_PDB_ins_code",             // 4-5
        "end_auth_asym_id", "end_label_comp_id",                 // 6-7
        "end_auth_seq_id", "?pdbx_end_PDB_ins_code"})) {         // 8-9
    Sheet& sheet = impl::find_or_add(sheets, row.str(0));
    sheet.strands.emplace_back();
    Sheet::Strand& strand = sheet.strands.back();
    strand.name = row.str(1);
    strand.start.chain_name = row.str(2);
    strand.start.res_id = make_resid(row.str(3), row.str(4), row.ptr_at(5));
    strand.end.chain_name = row.str(6);
    strand.end.res_id = make_resid(row.str(7), row.str(8), row.ptr_at(9));
  }

  // below we assume that range_id_1 is the strand preceding range_id_2
  for (const auto row : block.find("_struct_sheet_order.", {
        "sheet_id", "range_id_2", "sense"}))
    if (Sheet* sheet = impl::find_or_null(sheets, row.str(0)))
      if (Sheet::Strand* ss = impl::find_or_null(sheet->strands, row.str(1)))
        switch (alpha_up(row.str(2)[0])) {
          case 'P': ss->sense = 1; break; // parallel
          case 'A': ss->sense = -1; break; // anti-parallel
        }

  for (const auto row : block.find("_pdbx_struct_sheet_hbond.", {
        "sheet_id", "range_id_2",
        "range_1_auth_asym_id", "range_1_label_comp_id",
        "range_1_auth_seq_id", "?range_1_PDB_ins_code",
        "range_1_label_atom_id",
        "range_2_auth_asym_id", "range_2_label_comp_id",
        "range_2_auth_seq_id", "?range_2_PDB_ins_code",
        "range_2_label_atom_id"}))
    if (Sheet* sheet = impl::find_or_null(sheets, row.str(0)))
      if (Sheet::Strand* ss = impl::find_or_null(sheet->strands, row.str(1))) {
        ss->hbond_atom1.chain_name = row.str(2);
        ss->hbond_atom1.res_id = make_resid(row.str(3), row.str(4),
                                            row.ptr_at(5));
        ss->hbond_atom1.atom_name = row.str(6);
        ss->hbond_atom2.chain_name = row.str(7);
        ss->hbond_atom2.res_id = make_resid(row.str(8), row.str(9),
                                            row.ptr_at(10));
        ss->hbond_atom2.atom_name = row.str(11);
      }

  return sheets;
}

void set_part_of_address_from_label(AtomAddress& a, const Model& model,
                                    const std::string& label_asym,
                                    const std::string& label_seq_id_raw) {
  int seq = cif::as_int(label_seq_id_raw, SeqId::OptionalNum::None);
  for (const Chain& chain : model.chains)
    if (ConstResidueSpan sub = chain.get_subchain(label_asym)) {
      a.chain_name = chain.name;
      for (const Residue& res : sub)
        if (res.label_seq == seq) {
          a.res_id.seqid = res.seqid;
          return;
        }
    }
}

void read_connectivity(cif::Block& block, Structure& st) {
  enum {
    kId=0, kConnTypeId=1,
    kAuthAsymId=2/*-3*/,  kLabelAsymId=4/*-5*/, kLabelCompId=6/*-7*/,
    kLabelAtomId=8/*-9*/, kLabelAltId=10/*-11*/,
    kAuthSeqId=12/*-13*/, kLabelSeqId=14/*-15*/, kInsCode=16/*-17*/,
    kSym1=18, kSym2=19, kDistValue=20, kLinkId=21
  };
  // label_ identifiers are not sufficient for HOH:
  // waters have null label_seq_id so we need auth_seq_id+icode.
  // And since we need auth_seq_id, we also use auth_asym_id for consistency.
  // Unless only label_*_id are available.
  for (const auto row : block.find("_struct_conn.", {
        "id", "conn_type_id",                                   // 0-1
        "?ptnr1_auth_asym_id", "?ptnr2_auth_asym_id",           // 2-3
        "?ptnr1_label_asym_id", "?ptnr2_label_asym_id",         // 4-5
        "ptnr1_label_comp_id", "ptnr2_label_comp_id",           // 6-7
        "ptnr1_label_atom_id", "ptnr2_label_atom_id",           // 8-9
        "?pdbx_ptnr1_label_alt_id", "?pdbx_ptnr2_label_alt_id", // 10-11
        "?ptnr1_auth_seq_id", "?ptnr2_auth_seq_id",             // 12-13
        "?ptnr1_label_seq_id", "?ptnr2_label_seq_id",           // 14-15
        "?pdbx_ptnr1_PDB_ins_code", "?pdbx_ptnr2_PDB_ins_code", // 16-17
        "?ptnr1_symmetry", "?ptnr2_symmetry",                   // 18-19
        "?pdbx_dist_value", "?ccp4_link_id"})) {                // 20-21
    Connection c;
    c.name = row.str(kId);
    copy_string(row, kLinkId, c.link_id);
    c.type = connection_type_from_string(row.str(kConnTypeId));
    if (row.has2(kSym1) && row.has2(kSym2)) {
      std::string s1 = row.str(kSym1);
      std::string s2 = row.str(kSym2);
      if (s1 == s2) {
        c.asu = Asu::Same;
      } else {
        c.asu = Asu::Different;
        size_t sep1 = s1.find('_');
        size_t sep2 = s2.find('_');
        if (sep1 != std::string::npos && sep1 + 4 == s1.size() &&
            sep2 != std::string::npos && sep2 + 4 == s2.size()) {
          if (s1[0] == '1' && s1[1] == '_')  // symop1 is usually 1_555
            c.reported_sym[0] = no_sign_atoi(s2.c_str());
          else
            c.reported_sym[0] = 99;
          for (size_t i = 1; i <= 3; ++i)
            c.reported_sym[i] = s2[sep2 + i] - s1[sep1 + i];
        }
      }
    }
    copy_double(row, kDistValue, c.reported_distance);
    for (int i = 0; i < 2; ++i) {
      AtomAddress& a = (i == 0 ? c.partner1 : c.partner2);
      if (row.has(kAuthAsymId+i) && row.has(kAuthSeqId+i)) {
        a.chain_name = row.str(kAuthAsymId+i);
        a.res_id = make_resid(row.str(kLabelCompId+i),
                              row.str(kAuthSeqId+i), row.ptr_at(kInsCode+i));
      } else if (row.has(kLabelAsymId+i) && row.has(kLabelSeqId+i)) {
        set_part_of_address_from_label(a, st.first_model(),
                                       row.str(kLabelAsymId+i),
                                       row[kLabelSeqId+i]);
        a.res_id.name = row.str(kLabelCompId+i);
      } else {
        fail("_struct_conn without either _auth_ or _label_ asym_id+seq_id");
      }
      a.atom_name = row.str(kLabelAtomId+i);
      if (row.has2(kLabelAltId+i))
        a.altloc = cif::as_char(row[kLabelAltId+i], '\0');
    }
    st.connections.emplace_back(c);
  }
}

// CISPEP equivalent
void read_prot_cis(cif::Block& block, Structure& st) {
  enum {
    kModelNum=0,
    kAuthAsymId=1, kAuthSeqId=2, kInsCode=3, kLabelCompId=4, kAuthCompId=5,
    kAuthAsymId2=6, kAuthSeqId2=7, kInsCode2=8, kLabelCompId2=9, kAuthCompId2=10,
    kAltId=11, kOmegaAngle=12
  };
  // We could use label_seq_id etc and call set_part_of_address_from_label(),
  // but for now let's assume that auth_seq_id etc are there.
  for (auto row : block.find("_struct_mon_prot_cis.",
                             {"pdbx_PDB_model_num",                  // 0
                              "auth_asym_id",                        // 1
                              "auth_seq_id", "?pdbx_PDB_ins_code",   // 2-3
                              "?label_comp_id", "?auth_comp_id",     // 4-5
                              "?pdbx_auth_asym_id_2",                // 6
                              "?pdbx_auth_seq_id_2", "?pdbx_PDB_ins_code_2",   // 7-8
                              "?pdbx_label_comp_id_2", "?pdbx_auth_comp_id_2", // 9-10
                              "?label_alt_id", "?pdbx_omega_angle"})) {        // 11-12
    CisPep cispep;
    cispep.model_num = cif::as_int(row[kModelNum], 0);
    cispep.partner_c.chain_name = row.str(kAuthAsymId);
    cispep.partner_c.res_id.seqid = make_seqid(row.str(kAuthSeqId), row.ptr_at(kInsCode));
    cispep.partner_c.res_id.name = cif::as_string(row.one_of(kAuthCompId, kLabelCompId));
    if (row.has(kAuthAsymId2))
      cispep.partner_n.chain_name = row.str(kAuthAsymId2);
    if (row.has(kAuthSeqId2))
      cispep.partner_n.res_id.seqid = make_seqid(row.str(kAuthSeqId2), row.ptr_at(kInsCode2));
    cispep.partner_n.res_id.name = cif::as_string(row.one_of(kAuthCompId2, kLabelCompId2));
    if (row.has(kAltId))
      cispep.only_altloc = cif::as_char(row[kAltId], '\0');
    if (row.has(kOmegaAngle))
      cispep.reported_angle = cif::as_number(row[kOmegaAngle]);
    st.cispeps.push_back(cispep);
  }
}

// MODRES equivalent
void read_struct_mod_residue(cif::Block& block, Structure& st) {
  // Here auth_asym_id etc are mandatory and label_asym_id etc optional.
  for (auto row : block.find("_pdbx_struct_mod_residue.",
                             {"auth_asym_id",  // 0
                              "auth_seq_id", "?PDB_ins_code",  // 1-2
                              "?auth_comp_id", "?label_comp_id",  // 3-4
                              "?parent_comp_id", "?details",  // 5-6
                              "?ccp4_mod_id"})) {  // 7
    ModRes modres;
    modres.chain_name = row.str(0);
    modres.res_id.seqid = make_seqid(row.str(1), row.ptr_at(2));
    modres.res_id.name = row.one_of(3, 4);
    if (row.has(5))
      modres.parent_comp_id = row.str(5);
    if (row.has(6))
      modres.details = row.str(6);
    if (row.has(7))
      modres.mod_id = row.str(7);
    st.mod_residues.push_back(modres);
  }
}

void read_struct_sites(cif::Block& block, Structure& st) {
  for (auto row : block.find("_struct_site.",
                             {"id", "?pdbx_evidence_code",
                              "?pdbx_auth_asym_id", "?pdbx_auth_comp_id",
                              "?pdbx_auth_seq_id", "?pdbx_auth_ins_code",
                              "?pdbx_num_residues", "?details"})) {
    StructSite& site = impl::find_or_add(st.sites, row.str(0));
    copy_string(row, 1, site.evidence_code);
    if (row.has2(2))
      site.residue.chain_name = row.str(2);
    if (row.has2(3))
      site.residue.res_id.name = row.str(3);
    if (row.has2(4))
      site.residue.res_id.seqid = make_seqid(row.str(4), row.ptr_at(5));
    if (row.has2(6))
      site.residue_count = cif::as_int(row[6], -1);
    copy_string(row, 7, site.details);
  }

  for (auto row : block.find("_struct_site_gen.",
                             {"site_id", "?pdbx_num_res",
                              "?label_comp_id", "?label_asym_id",
                              "?label_seq_id", "?pdbx_auth_ins_code",
                              "?auth_comp_id", "?auth_asym_id",
                              "?auth_seq_id", "?label_atom_id",
                              "?label_alt_id", "?auth_atom_id",
                              "?symmetry", "?details"})) {
    StructSite& site = impl::find_or_add(st.sites, row.str(0));
    site.members.emplace_back();
    StructSite::Member& member = site.members.back();
    if (row.has2(1))
      member.residue_num = cif::as_int(row[1], -1);
    copy_string(row, 2, member.label_comp_id);
    copy_string(row, 3, member.label_asym_id);
    if (row.has2(4))
      member.label_seq = cif::as_int(row[4], SeqId::OptionalNum::None);
    copy_string(row, 9, member.label_atom_id);
    if (row.has2(10))
      member.label_alt_id = cif::as_char(row[10], '\0');
    if (row.has2(11))
      member.auth.atom_name = row.str(11);
    if (member.label_alt_id != '\0' && !member.auth.atom_name.empty())
      member.auth.altloc = member.label_alt_id;
    copy_string(row, 12, member.symmetry);
    copy_string(row, 13, member.details);
    if (row.has2(6))
      member.auth.res_id.name = row.str(6);
    else if (row.has2(2))
      member.auth.res_id.name = row.str(2);
    if (row.has2(7))
      member.auth.chain_name = row.str(7);
    if (row.has2(8))
      member.auth.res_id.seqid = make_seqid(row.str(8), row.ptr_at(5));
    else if (!st.models.empty() && row.has2(3) && row.has2(4))
      set_part_of_address_from_label(member.auth, st.models[0], row.str(3), row.str(4));
  }

  for (StructSite& site : st.sites)
    if (site.residue_count < 0 && !site.members.empty())
      site.residue_count = (int) site.members.size();
}

// Operation expression is an item type used for *.oper_expression.
// Here, to keep it simple, we ignore products such as "(2)(3)".
// We parse "3", "1,3,5", "one,two", "(3)", "(a)", "(1-60)", "(2,3-8,XY)", etc
std::vector<std::string> parse_operation_expr(const std::string& expr) {
  std::vector<std::string> result;
  std::size_t start = 0;
  std::size_t close_br = std::string::npos;
  if (expr[0] == '(') {
    start = 1;
    close_br = expr.find(')');
  }
  for (;;) {
    std::size_t sep = std::min(expr.find(',', start), close_br);
    std::size_t minus = expr.find('-', start);
    if (minus < sep) {
      int n_min = no_sign_atoi(expr.c_str() + start);
      int n_max = no_sign_atoi(expr.c_str() + minus + 1);
      for (int n = n_min; n <= n_max; ++n)
        result.push_back(std::to_string(n));
    } else {
      result.emplace_back(expr, start, sep - start);
    }
    if (sep == close_br)
      break;
    start = sep + 1;
  }
  return result;
}

std::vector<Assembly> read_assemblies(cif::Block& block) {
  std::vector<Assembly> assemblies;
  cif::Table prop_tab = block.find("_pdbx_struct_assembly_prop.",
                                   {"biol_id", "type", "value"});
  cif::Table gen_tab = block.find("_pdbx_struct_assembly_gen.",
                          {"assembly_id", "oper_expression", "asym_id_list"});
  std::vector<Assembly::Operator> oper_list;
  std::vector<std::string> oper_list_tags = transform_tags("matrix", "vector");
  oper_list_tags.emplace_back("id");  // 12
  oper_list_tags.emplace_back("type");  // 13
  for (const auto row : block.find("_pdbx_struct_oper_list.", oper_list_tags)) {
    oper_list.emplace_back();
    oper_list.back().name = row.str(12);
    oper_list.back().type = row.str(13);
    oper_list.back().transform = get_transform_matrix(row);
  }
  for (const auto row : block.find("_pdbx_struct_assembly.", {
        "id", "details", "method_details",
        "oligomeric_details", "oligomeric_count"})) {
    assemblies.emplace_back(row.str(0));
    Assembly& a = assemblies.back();
    std::string detail = row.str(1);
    if (detail == "author_and_software_defined_assembly")
      a.author_determined = a.software_determined = true;
    else if (detail == "author_defined_assembly")
      a.author_determined = true;
    else if (detail == "software_defined_assembly")
      a.software_determined = true;
    else if (detail == "complete icosahedral assembly")
      a.special_kind = Assembly::SpecialKind::CompleteIcosahedral;
    else if (detail == "representative helical assembly")
      a.special_kind = Assembly::SpecialKind::RepresentativeHelical;
    else if (detail == "complete point assembly")
      a.special_kind = Assembly::SpecialKind::CompletePoint;

    if (!a.author_determined && !a.software_determined &&
        a.special_kind == Assembly::SpecialKind::NA && !detail.empty()) {
      assemblies.pop_back();
      continue;
    }
    if (a.software_determined && !cif::is_null(row[2]))
      a.software_name = row.str(2);  // method_details
    a.oligomeric_details = row.str(3);
    a.oligomeric_count = cif::as_int(row[4], 0);
    for (const auto row_p : prop_tab)
      if (row_p.str(0) == a.name) {
        std::string type = row_p.str(1);
        double value = cif::as_number(row_p[2]);
        if (type == "ABSA (A^2)")
          a.absa = value;
        else if (type == "SSA (A^2)")
          a.ssa = value;
        else if (type == "MORE")
          a.more = value;
      }
    for (const auto row_g : gen_tab)
      if (row_g.str(0) == a.name) {
        a.generators.emplace_back();
        Assembly::Gen& gen = a.generators.back();
        split_str_into(row_g.str(2), ',', gen.subchains);
        for (const std::string& name : parse_operation_expr(row_g.str(1)))
          if (const Assembly::Operator* oper = impl::find_or_null(oper_list, name))
            gen.operators.push_back(*oper);
      }
  }
  return assemblies;
}

void fill_residue_entity_type(Structure& st) {
  for (Model& model : st.models)
    for (Chain& chain : model.chains)
      for (ResidueSpan& sub : chain.subchains()) {
        if (const Entity* ent = st.get_entity_of(sub)) {
          for (Residue& res : sub)
            res.entity_type = ent->entity_type;
        } else {
          // Don't attempt to distinguish Polymer, Branched and NonPolymer here.
          // Third-party software may not use the same conventions regarding
          // label_seq_id and label_asym_id that the PDB uses.
          for (Residue& res : sub)
            res.entity_type = res.is_water() ? EntityType::Water : EntityType::Unknown;
        }
      }
}

void read_sifts_unp(cif::Block& block, Structure& st) {
  enum { kEntityId=0, kAsymId, kSeqIdOrdinal, kSeqId, kObserved,
         kUnpRes, kUnpNum, kUnpAcc };
  cif::Table table = block.find("_pdbx_sifts_xref_db.", {
      "entity_id", "asym_id", "seq_id_ordinal", "seq_id", "observed",
      "unp_res", "unp_num", "unp_acc"});
  if (!table.ok())
    return;
  for (Model& model : st.models) {
    Entity* ent = nullptr;
    ResidueSpan polymer;
    Residue* res = nullptr;
    std::string unp_acc;
    SiftsUnpResidue unp;
    for (const auto row : table) {
      if (row[kSeqIdOrdinal] != "1" || row[kObserved][0] != 'y')
        continue;
      if (cif::is_null(row[kUnpAcc]) || cif::is_null(row[kUnpNum]))
        continue;
      bool update_acc_index = false;
      if (!ent || row[kEntityId] != ent->name) {
        ent = st.get_entity(row[kEntityId]);
        if (!ent)
          fail("_pdbx_sifts_xref_db: entity_id not found: " + row[kEntityId]);
        update_acc_index = true;
      }
      if (row[kUnpAcc] != unp_acc) {
        unp_acc = row.str(kUnpAcc);
        update_acc_index = true;
      }
      if (update_acc_index) {
        auto& vec = ent->sifts_unp_acc;
        auto it = std::find(vec.begin(), vec.end(), unp_acc);
        unp.acc_index = std::uint8_t(it - vec.begin());
        if (it == vec.end())
          vec.push_back(unp_acc);
      }
      if (!polymer || row[kAsymId] != polymer.front().subchain) {
        polymer = model.get_subchain(row[kAsymId]);
        if (!polymer)
          fail("_pdbx_sifts_xref_db: asym_id not found: " + row[kAsymId]);
        res = polymer.begin();
      } else if (res == polymer.end()) {
        res = polymer.begin();
      }
      int label_seq = cif::as_int(row[kSeqId]);
      if (res->label_seq != label_seq) {
        res = polymer.begin();
        while (res != polymer.end() && res->label_seq != label_seq)
          ++res;
      }
      if (res == polymer.end())
        continue;
      unp.res = cif::as_char(row[kUnpRes], '\0');
      int num = cif::as_int(row[kUnpNum]);
      unp.num = (std::uint16_t) num;
      if (num != (int)unp.num)
        fail("_pdbx_sifts_xref_db.unp_num: " + row[kUnpNum]);
      while (res->label_seq == label_seq && res != polymer.end()) {
        res->sifts_unp = unp;
        ++res;
      }
    }
  }
}

DiffractionInfo* find_diffrn(Metadata& meta, const std::string& diffrn_id) {
  for (CrystalInfo& crystal_info : meta.crystals)
    for (DiffractionInfo& diffr_info : crystal_info.diffractions)
      if (diffr_info.id == diffrn_id)
        return &diffr_info;
  return nullptr;
}

// optimized Row::one_of(), use with care or it will crash a program
struct RowAccess {
  const std::string *val = nullptr;
  const std::string *fallback = nullptr;
  RowAccess(const cif::Table& tab, int n1, int n2) {
    int pos1 = tab.positions.at(n1);
    int pos2 = tab.positions.at(n2);
    if (pos1 < 0) {
      pos1 = pos2;
      pos2 = -1;
    }
    const cif::Loop* loop = const_cast<cif::Table&>(tab).get_loop();
    if (pos1 >= 0)
      val = loop ? &loop->values[pos1] : &tab.bloc.items[pos1].pair[1];
    if (pos2 >= 0)
      fallback = loop ? &loop->values[pos2] : &tab.bloc.items[pos2].pair[1];
  }
  bool ok() const { return val != nullptr; }
  const std::string& get(size_t gap) const {
    const std::string& r = val[gap];
    if (!cif::is_null(r) || fallback == nullptr)
      return r;
    return fallback[gap];
  }
};

template<class T>
T* get_by_id(std::vector<T>& vec, const std::string& id) {
  for (T& item : vec)
    if (item.id == id)
      return &item;
  return nullptr;
}

void read_entry_info(cif::Block& block, gemmi::Structure& st) {
    auto add_info = [&](const std::string& tag) {
        bool first = true;
        for (const std::string& v : block.find_values(tag))
            if (!cif::is_null(v)) {
                if (first)
                    st.info[tag] = cif::as_string(v);
                else
                    st.info[tag] += "; " + cif::as_string(v);
                first = false;
            }
    };
    add_info("_entry.id");
    add_info("_cell.Z_PDB");
    add_info("_exptl.method");
    add_info("_struct.title");
    // in pdbx/mmcif v5 date_original was replaced with a much longer tag
    std::string old_date_tag = "_database_PDB_rev.date_original";
    std::string new_date_tag = "_pdbx_database_status.recvd_initial_deposition_date";
    add_info(old_date_tag);
    add_info(new_date_tag);
    if (st.info.count(old_date_tag) == 1 && st.info.count(new_date_tag) == 0)
        st.info[new_date_tag] = st.info[old_date_tag];
    add_info("_struct_keywords.pdbx_keywords");
    add_info("_struct_keywords.text");
}

void read_audit_author(cif::Block& block, Structure& st) {
    for (const std::string& v : block.find_values("_audit_author.name"))
        if (!cif::is_null(v))
            st.meta.authors.push_back(cif::as_string(v));
}

void read_refinement_info(cif::Block& block, Structure& st) {
    for (auto row : block.find("_refine.", {"pdbx_refine_id",           // 0
                                            "?ls_d_res_high",           // 1
                                            "?ls_d_res_low",            // 2
                                            "?ls_percent_reflns_obs",   // 3
                                            "?ls_number_reflns_obs",    // 4
                                            "?ls_number_reflns_R_work", // 5
                                            "?ls_number_reflns_R_free", // 6
                                            "?ls_R_factor_obs",         // 7
                                            "?ls_R_factor_R_work",      // 8
                                            "?ls_R_factor_R_free"})) {
        st.meta.refinement.emplace_back();
        RefinementInfo& ref = st.meta.refinement.back();
        ref.id = row.str(0);
        if (row.has(1)) {
            ref.resolution_high = cif::as_number(row[1]);
            if (ref.resolution_high > 0 &&
                (st.resolution == 0 || ref.resolution_high < st.resolution))
                st.resolution = ref.resolution_high;
        }
        copy_double(row, 2, ref.resolution_low);
        copy_double(row, 3, ref.completeness);
        copy_int(row, 4, ref.reflection_count);
        copy_int(row, 5, ref.work_set_count);
        copy_int(row, 6, ref.rfree_set_count);
        copy_double(row, 7, ref.r_all);
        copy_double(row, 8, ref.r_work);
        copy_double(row, 9, ref.r_free);
    }
    if (st.resolution == 0.) {
      const std::string* em_res = block.find_value("_em_3d_reconstruction.resolution");
      if (em_res)
        st.resolution = cif::as_number(*em_res);

    }
}

void read_tls_info(cif::Block& block, Structure& st) {
    for (auto row : block.find("_pdbx_refine_tls.", {
        "id", "?pdbx_refine_id",
        "T[1][1]", "T[2][2]", "T[3][3]", "T[1][2]", "T[1][3]", "T[2][3]",
        "L[1][1]", "L[2][2]", "L[3][3]", "L[1][2]", "L[1][3]", "L[2][3]",
        "S[1][1]", "S[1][2]", "S[1][3]",
        "S[2][1]", "S[2][2]", "S[2][3]",
        "S[3][1]", "S[3][2]", "S[3][3]",
        "origin_x", "origin_y", "origin_z"})) {
        if (st.meta.refinement.empty())
            break;
        RefinementInfo* ref = nullptr;
        if (row.has(1))
            ref = get_by_id(st.meta.refinement, row.str(1));
        if (!ref)
            ref = &st.meta.refinement[0];
        ref->tls_groups.emplace_back();
        TlsGroup& tls = ref->tls_groups.back();
        tls.id = row.str(0);
        tls.num_id = (short) no_sign_atoi(tls.id.c_str());
        tls.T = get_smat33<double>(row, 2);
        tls.L = get_smat33<double>(row, 8);
        for (int i = 0; i < 3; ++i)
            for (int j = 0; j < 3; ++j)
                tls.S[i][j] = cif::as_number(row[14+3*i+j]);
        tls.origin.x = cif::as_number(row[23]);
        tls.origin.y = cif::as_number(row[24]);
        tls.origin.z = cif::as_number(row[25]);
    }
    for (auto row : block.find("_pdbx_refine_tls_group.", {
        "refine_tls_id", "?beg_auth_asym_id", "?beg_auth_seq_id", "?beg_PDB_ins_code",
        "?end_auth_seq_id", "?end_PDB_ins_code", "?selection_details"})) {
        for (RefinementInfo& ref : st.meta.refinement)
            if (TlsGroup* tls = get_by_id(ref.tls_groups, row.str(0))) {
                tls->selections.emplace_back();
                TlsGroup::Selection& sel = tls->selections.back();
                if (row.has(1))
                    sel.chain = row.str(1);
                if (row.has(2))
                    sel.res_begin = make_seqid(row.str(2), row.ptr_at(3));
                if (row.has(4))
                    sel.res_end = make_seqid(row.str(4), row.ptr_at(5));
                if (row.has(6))
                    sel.details = row.str(6);
                break;
            }
    }
}

void read_experimental_info(cif::Block& block, Structure& st) {
    for (auto row : block.find("_exptl.", {"method", "?crystals_number"})) {
        st.meta.experiments.emplace_back();
        st.meta.experiments.back().method = row.str(0);
        copy_int(row, 1, st.meta.experiments.back().number_of_crystals);
    }

    for (auto row : block.find("_exptl_crystal.", {"id", "?description"})) {
        st.meta.crystals.emplace_back();
        st.meta.crystals.back().id = row.str(0);
        copy_string(row, 1, st.meta.crystals.back().description);
    }

    for (auto row : block.find("_diffrn.",
                               {"id", "crystal_id", "?ambient_temp"})) {
        std::string id = row.str(1);
        auto cryst = std::find_if(st.meta.crystals.begin(), st.meta.crystals.end(),
                                  [&](const CrystalInfo& c) { return c.id == id; });
        if (cryst != st.meta.crystals.end()) {
            cryst->diffractions.emplace_back();
            cryst->diffractions.back().id = row.str(0);
            copy_double(row, 2, cryst->diffractions.back().temperature);
        }
    }
    for (auto row : block.find("_diffrn_detector.", {"diffrn_id",
                                                     "?pdbx_collection_date",
                                                     "?detector",
                                                     "?type",
                                                     "?details"}))
        if (DiffractionInfo* di = find_diffrn(st.meta, row.str(0))) {
            copy_string(row, 1, di->collection_date);
            copy_string(row, 2, di->detector);
            copy_string(row, 3, di->detector_make);
            copy_string(row, 4, di->optics);
        }
    for (auto row : block.find("_diffrn_radiation.",
                               {"diffrn_id",
                                "?pdbx_scattering_type",
                                "?pdbx_monochromatic_or_laue_m_l",
                                "?monochromator"}))
        if (DiffractionInfo* di = find_diffrn(st.meta, row.str(0))) {
            copy_string(row, 1, di->scattering_type);
            if (row.has2(2))
                di->mono_or_laue = row.str(2)[0];
            copy_string(row, 3, di->monochromator);
        }
    for (auto row : block.find("_diffrn_source.", {"diffrn_id",
                                                   "?source",
                                                   "?type",
                                                   "?pdbx_synchrotron_site",
                                                   "?pdbx_synchrotron_beamline",
                                                   "?pdbx_wavelength_list"}))
        if (DiffractionInfo* di = find_diffrn(st.meta, row.str(0))) {
            copy_string(row, 1, di->source);
            copy_string(row, 2, di->source_type);
            copy_string(row, 3, di->synchrotron);
            copy_string(row, 4, di->beamline);
            copy_string(row, 5, di->wavelengths);
        }
}

void read_reflns_info(cif::Block& block, Structure& st) {
    size_t n = 0;
    for (auto row : block.find("_reflns.", {"pdbx_diffrn_id",        // 0
                                            "?number_obs",           // 1
                                            "?d_resolution_high",    // 2
                                            "?d_resolution_low",     // 3
                                            "?percent_possible_obs", // 4
                                            "?pdbx_redundancy",      // 5
                                            "?pdbx_Rmerge_I_obs",    // 6
                                            "?pdbx_Rsym_value",      // 7
                                            "?pdbx_netI_over_sigmaI"})) {
        // In the case of multiple experiments (_exptl), which is rare,
        // it is not explicit to which experiment which data statistics
        // (_reflns) corresponds to. We assume they are in the same order.
        if (n >= st.meta.experiments.size())
            break;
        ExperimentInfo& exper = st.meta.experiments[n++];
        split_str_into(row.str(0), ',', exper.diffraction_ids);
        copy_int(row, 1, exper.unique_reflections);
        copy_double(row, 2, exper.reflections.resolution_high);
        copy_double(row, 3, exper.reflections.resolution_low);
        copy_double(row, 4, exper.reflections.completeness);
        copy_double(row, 5, exper.reflections.redundancy);
        copy_double(row, 6, exper.reflections.r_merge);
        copy_double(row, 7, exper.reflections.r_sym);
        copy_double(row, 8, exper.reflections.mean_I_over_sigma);
    }
}

void read_software_info(cif::Block& block, Structure& st) {
    for (auto row : block.find("_software.", {"name",
                                              "?classification",
                                              "?version",
                                              "?date",
                                              "?description",
                                              "?contact_author",
                                              "?contact_author_email"})) {
        st.meta.software.emplace_back();
        SoftwareItem& item = st.meta.software.back();
        item.name = row.str(0);
        if (row.has2(1))
            item.classification = software_classification_from_string(row.str(1));
        copy_string(row, 2, item.version);
        copy_string(row, 3, item.date);
        copy_string(row, 4, item.description);
        copy_string(row, 5, item.contact_author);
        copy_string(row, 6, item.contact_author_email);
    }
}

void read_ncs_info(cif::Block& block, Structure& st) {
    std::vector<std::string> ncs_oper_tags = transform_tags("matrix", "vector");
    ncs_oper_tags.emplace_back("id");  // 12
    ncs_oper_tags.emplace_back("?code");  // 13
    cif::Table ncs_oper = block.find("_struct_ncs_oper.", ncs_oper_tags);
    for (auto op : ncs_oper) {
        bool given = op.has(13) && op.str(13) == "given";
        Transform tr = get_transform_matrix(op);
        if (tr.is_identity())
            // ignore identity, but store its id so we can write it back to mmCIF
            st.info["_struct_ncs_oper.id"] = op.str(12);
        else if (tr.has_nan())
            // As of 2022 some entries (7qb5, 6tsd) have incomplete _struct_ncs_oper.
            // It is safer to skip them.
            continue;
        else
            st.ncs.push_back({op.str(12), given, tr});
    }
}

void read_atom_sites(cif::Block& block, Structure& st) {
    auto aniso_map = get_anisotropic_u(block);

    // atom list
    enum { kId=0, kGroupPdb, kSymbol, kLabelAtomId, kAltId, kLabelCompId,
           kLabelAsymId, kLabelEntityId, kLabelSeqId, kInsCode,
           kX, kY, kZ, kOcc, kBiso, kCharge,
           kAuthSeqId, kAuthCompId, kAuthAsymId, kAuthAtomId, kModelNum,
           kCalcFlag, kTlsGroupId, kDeuterium };
    cif::Table atom_table = block.find("_atom_site.",
                                       {"id",
                                        "?group_PDB",
                                        "type_symbol",
                                        "?label_atom_id",
                                        "label_alt_id",
                                        "?label_comp_id",
                                        "label_asym_id",
                                        "?label_entity_id",
                                        "?label_seq_id",
                                        "?pdbx_PDB_ins_code",
                                        "Cartn_x",
                                        "Cartn_y",
                                        "Cartn_z",
                                        "?occupancy",
                                        "?B_iso_or_equiv",
                                        "?pdbx_formal_charge",
                                        "?auth_seq_id",
                                        "?auth_comp_id",
                                        "?auth_asym_id",
                                        "?auth_atom_id",
                                        "?pdbx_PDB_model_num",
                                        "?calc_flag",
                                        "?pdbx_tls_group_id",
                                        "?ccp4_deuterium_fraction",
                                       });
    if (atom_table.length() != 0) {
        RowAccess asym_id(atom_table, kAuthAsymId, kLabelAsymId);
        // we use only one comp (residue) and one atom name
        RowAccess comp_id(atom_table, kAuthCompId, kLabelCompId);
        RowAccess atom_id(atom_table, kAuthAtomId, kLabelAtomId);
        RowAccess seq_id(atom_table, kAuthSeqId, kLabelSeqId);
        if (!asym_id.ok())
            fail("Neither _atom_site.label_asym_id nor auth_asym_id found");
        if (!comp_id.ok())
            fail("Neither _atom_site.label_comp_id nor auth_comp_id found");
        if (!atom_id.ok())
            fail("Neither _atom_site.label_atom_id nor auth_atom_id found");
        if (!seq_id.ok())
            fail("Neither _atom_site.label_seq_id nor auth_seq_id found");
        size_t loop_width = 0;
        if (const cif::Loop* loop = atom_table.get_loop())
            loop_width = loop->width();

        st.has_d_fraction = atom_table.has_column(kDeuterium);

        Model *model = nullptr;
        Chain *chain = nullptr;
        Residue *resi = nullptr;
        std::string model_num;
        if (!atom_table.has_column(kModelNum)) {
            st.models.emplace_back(1);
            model = &st.models[0];
        }
        for (auto row : atom_table) {
            size_t gap = row.row_index * loop_width;
            if (row.has(kModelNum) && row[kModelNum] != model_num) {
                model_num = row[kModelNum];
                model = &st.find_or_add_model(cif::as_int(model_num, 0));
                chain = nullptr;
            }
            if (!chain || cif::as_string(asym_id.get(gap)) != chain->name) {
                model->chains.emplace_back(cif::as_string(asym_id.get(gap)));
                chain = &model->chains.back();
                resi = nullptr;
            }
            ResidueId rid = make_resid(cif::as_string(comp_id.get(gap)),
                                       cif::as_string(seq_id.get(gap)),
                                       row.has(kInsCode) ? &row[kInsCode] : nullptr);
            if (!resi || !resi->matches(rid)) {
                resi = chain->find_or_add_residue(rid);
                if (resi->atoms.empty()) {
                    if (row.has2(kLabelSeqId))
                        resi->label_seq = cif::as_int(row[kLabelSeqId]);
                    resi->subchain = row.str(kLabelAsymId);
                    if (row.has2(kLabelEntityId))
                        resi->entity_id = row.str(kLabelEntityId);
                    // don't check if group_PDB is consistent, it's not that important
                    if (row.has2(kGroupPdb))
                        for (int i = 0; i < 2; ++i) { // first character could be " or '
                            const char c = alpha_up(row[kGroupPdb][i]);
                            if (c == 'A' || c == 'H' || c == '\0')
                                resi->het_flag = c;
                        }
                }
            } else if (resi->seqid != rid.seqid) {
                fail("Inconsistent sequence ID: " + resi->str() + " / " + rid.str());
            }
            Atom atom;
            atom.name = cif::as_string(atom_id.get(gap));
            // altloc is always a single letter (not guaranteed by the mmCIF spec)
            atom.altloc = cif::as_char(row[kAltId], '\0');
            atom.charge = row.has2(kCharge) ? cif::as_int(row[kCharge]) : 0;
            atom.element = gemmi::Element(cif::as_string(row[kSymbol]));
            // According to the PDBx/mmCIF spec _atom_site.id can be a string,
            // but in all the files it is a serial number; its value is not essential,
            // so we just ignore non-integer ids.
            atom.serial = string_to_int(row[kId], false);
            if (st.has_d_fraction)
                atom.fraction = (float) cif::as_number(row[kDeuterium], 0.);
            if (row.has2(kCalcFlag)) {
                const std::string& cf = row[kCalcFlag];
                if (cf[0] == 'c')
                    atom.calc_flag = CalcFlag::Calculated;
                if (cf[0] == 'd')
                    atom.calc_flag = cf[1] == 'u' ? CalcFlag::Dummy
                                                  : CalcFlag::Determined;
            }
            if (row.has2(kTlsGroupId)) {
                const char* str = row[kTlsGroupId].c_str();
                const char* endptr;
                int tls_id = no_sign_atoi(str, &endptr);
                if (endptr != str)
                    atom.tls_group_id = (short) tls_id;
            }
            atom.pos.x = cif::as_number(row[kX]);
            atom.pos.y = cif::as_number(row[kY]);
            atom.pos.z = cif::as_number(row[kZ]);
            if (row.has2(kOcc))
                atom.occ = (float) cif::as_number(row[kOcc]);
            if (row.has2(kBiso))
                atom.b_iso = (float) cif::as_number(row[kBiso]);

            if (!aniso_map.empty()) {
                auto ani = aniso_map.find(row[kId]);
                if (ani != aniso_map.end())
                    atom.aniso = ani->second;
            }
            resi->atoms.emplace_back(atom);
        }
    }
}

void read_entity_and_sequence_info(cif::Block& block, Structure& st) {
    cif::Table polymer_types = block.find("_entity_poly.", {"entity_id", "type"});
    for (auto row : block.find("_entity.", {"id", "?type"})) {
        Entity ent(row.str(0));
        if (row.has(1))
            ent.entity_type = entity_type_from_string(row.str(1));
        ent.polymer_type = PolymerType::Unknown;
        if (polymer_types.ok()) {
            try {
                std::string poly_type = polymer_types.find_row(ent.name).str(1);
                if (ent.entity_type == EntityType::Unknown)
                    ent.entity_type = EntityType::Polymer;
                ent.polymer_type = polymer_type_from_string(poly_type);
            } catch (std::runtime_error&) {}
        }
        // _entity_poly_seq is supposed to reflect heterogeneities in _atom_site.
        ent.reflects_microhetero = true;
        st.entities.push_back(ent);
    }

    for (auto row : block.find("_entity_poly_seq.",
                               {"entity_id", "num", "mon_id"}))
        if (Entity* ent = st.get_entity(row.str(0))) {
            // According to the spec, num must be >= 1.
            int pos = cif::as_int(row[1], 0) - 1;
            if (pos == (int) ent->full_sequence.size())
                ent->full_sequence.push_back(row.str(2));
            else if (pos >= 0 && pos < (int) ent->full_sequence.size())
                cat_to(ent->full_sequence[pos], ',', row.str(2));
        }

    cif::Table struct_ref = block.find("_struct_ref.",
        {"id", "entity_id", "db_name", "db_code",
         "?pdbx_db_accession", "?pdbx_db_isoform"});
    cif::Table struct_ref_seq = block.find("_struct_ref_seq.",
        {"ref_id", "seq_align_beg", "seq_align_end",                   // 0-2
         "db_align_beg", "db_align_end",                               // 3-4
         "?pdbx_auth_seq_align_beg", "?pdbx_seq_align_beg_ins_code",   // 5-6
         "?pdbx_auth_seq_align_end", "?pdbx_seq_align_end_ins_code"}); // 7-8
    // DbRef doesn't correspond 1:1 to the mmCIF tables; we need to remove
    // duplicates from _struct_ref_seq to make it work.
    std::vector<std::string> seen;
    for (cif::Table::Row seq : struct_ref_seq) {
        std::string str = seq[0];
        for (int i = 1; i < 5; ++i) {
            str += '\t';
            str += seq[i];
        }
        if (in_vector(str, seen))
            continue;
        seen.push_back(str);
        cif::Table::Row row = struct_ref.find_row(seq.str(0));
        if (Entity* ent = st.get_entity(row.str(1))) {
            ent->dbrefs.emplace_back();
            Entity::DbRef& dbref = ent->dbrefs.back();
            dbref.db_name = row.str(2);
            dbref.id_code = row.str(3);
            if (row.has(4))
                dbref.accession_code = row.str(4);
            if (row.has(5))
                dbref.isoform = row.str(5);
            constexpr int None = SeqId::OptionalNum::None;
            dbref.label_seq_begin = cif::as_int(seq[1], None);
            dbref.label_seq_end = cif::as_int(seq[2], None);
            dbref.db_begin.num = cif::as_int(seq[3], None);
            dbref.db_end.num = cif::as_int(seq[4], None);
            if (seq.has(5))
                dbref.seq_begin = make_seqid(seq.str(5), seq.ptr_at(6));
            if (seq.has(7))
                dbref.seq_end = make_seqid(seq.str(7), seq.ptr_at(8));
        }
    }

    cif::Table s_asym_table = block.find("_struct_asym.", {"id", "entity_id"});
    if (s_asym_table.ok()) {
        for (auto row : s_asym_table)
            if (Entity* ent = st.get_entity(row.str(1)))
                ent->subchains.push_back(row.str(0));
    } else if (!st.models.empty()) {
        for (const Chain& chain : st.models[0].chains)
            for (const ConstResidueSpan& sub : chain.subchains()) {
                const Residue& r = sub.front();
                if (Entity* ent = st.get_entity(r.entity_id))
                    if (!in_vector(r.subchain, ent->subchains))
                        ent->subchains.push_back(r.subchain);
            }
    }
}

} // anonymous namespace


void populate_structure_from_block(const cif::Block& block_, Structure& st) {
  // find() and Table don't have const variants, but we don't change anything.
  cif::Block& block = const_cast<cif::Block&>(block_);
  st.input_format = CoorFormat::Mmcif;
  st.name = block.name;
  impl::set_cell_from_mmcif(block, st.cell);
  st.spacegroup_hm = cif::as_string(impl::find_spacegroup_hm_value(block));

  read_entry_info(block, st);
  read_audit_author(block, st);
  read_refinement_info(block, st);
  read_tls_info(block, st);
  read_experimental_info(block, st);
  read_reflns_info(block, st);
  read_software_info(block, st);
  read_ncs_info(block, st);

  // PDBx/mmcif spec defines both _database_PDB_matrix.scale* and
  // _atom_sites.fract_transf_* as equivalent of pdb SCALE, but the former
  // is not used, so we ignore it.
  cif::Table fract_tv = block.find("_atom_sites.fract_transf_",
                                   transform_tags("matrix", "vector"));
  if (fract_tv.length() > 0) {
    Transform fract = get_transform_matrix(fract_tv[0]);
    st.cell.set_matrices_from_fract(fract);
  }

  // We read/write origx just for completeness, it's not used anywhere.
  cif::Table origx_tv = block.find("_database_PDB_matrix.",
                                   transform_tags("origx", "origx_vector"));
  if (origx_tv.length() > 0) {
    st.has_origx = true;
    st.origx = get_transform_matrix(origx_tv[0]);
  }

  read_atom_sites(block, st);
  read_entity_and_sequence_info(block, st);
  fill_residue_entity_type(st);
  st.setup_cell_images();

  st.helices = read_helices(block);
  st.sheets = read_sheets(block);
  assign_residue_ss_from_file(st);
  read_connectivity(block, st);
  read_prot_cis(block, st);
  read_struct_mod_residue(block, st);
  read_struct_sites(block, st);
  st.assemblies = read_assemblies(block);
  read_sifts_unp(block, st);
  read_chemcomp_info(block, st);

  cif::Table chem_comp_table = block.find("_chem_comp.", {"id", "three_letter_code"});
  if (chem_comp_table.ok()) {
    for (auto row : chem_comp_table) {
      std::string alias = row.str(0);
      std::string long_id = row.str(1);
      if (alias[0] == '~' && long_id[0] != '~' && long_id[0] != '\0')
        st.shortened_ccd_codes.emplace_back(long_id, alias);
    }
    restore_full_ccd_codes(st);
  }
}


Residue make_residue_from_chemcomp_block(const cif::Block& block, ChemCompModel kind) {
  std::array<std::string, 3> xyz_tags;
  if (kind == ChemCompModel::First) {
    const cif::Item* loop_item =
        const_cast<cif::Block&>(block).find_loop("_chem_comp_atom.atom_id").item();
    if (loop_item && loop_item->type == cif::ItemType::Loop)
      for (const std::string& tag : loop_item->loop.tags) {
        std::string lctag = gemmi::to_lower(tag);
        if (lctag == "_chem_comp_atom.x") {
          kind = ChemCompModel::Xyz;
          break;
        } else if (lctag == "_chem_comp_atom.model_cartn_x") {
          kind = ChemCompModel::Example;
          break;
        } else if (lctag == "_chem_comp_atom.pdbx_model_cartn_x_ideal") {
          kind = ChemCompModel::Ideal;
          break;
        }
      }
  }
  switch (kind) {
    case ChemCompModel::Xyz:
      xyz_tags = {{"x", "y", "z"}};
      break;
    case ChemCompModel::Example:
      xyz_tags = {{"model_Cartn_x", "model_Cartn_y", "model_Cartn_z"}};
      break;
    case ChemCompModel::Ideal:
      xyz_tags = {{"pdbx_model_Cartn_x_ideal",
                   "pdbx_model_Cartn_y_ideal",
                   "pdbx_model_Cartn_z_ideal"}};
      break;
    default:
      break;
  }
  Residue res;
  res.seqid.num = 1;
  cif::Column col =
    const_cast<cif::Block&>(block).find_values("_chem_comp_atom.comp_id");
  if (col && col.length() > 0)
    res.name = col[0];
  else
    res.name = block.name.substr(starts_with(block.name, "comp_") ? 5 : 0);
  cif::Table table = const_cast<cif::Block&>(block).find("_chem_comp_atom.",
          {"atom_id", "type_symbol", "?charge",
           xyz_tags[0], xyz_tags[1], xyz_tags[2]});
  res.atoms.resize(table.length());
  int n = 0;
  for (auto row : table) {
    Atom& atom = res.atoms[n++];
    atom.name = row.str(0);
    atom.element = Element(row.str(1));
    if (row.has2(2))
      // Charge is defined as integer, but some cif files in the wild have
      // trailing '.000', so we read it as floating-point number.
      atom.charge = (signed char) std::round(cif::as_number(row[2]));
    atom.pos = Position(cif::as_number(row[3]),
                        cif::as_number(row[4]),
                        cif::as_number(row[5]));
  }
  return res;
}

} // namespace gemmi
