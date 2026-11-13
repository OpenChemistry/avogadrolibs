/// @file
/// @brief Metadata structures from coordinate files (PDB/mmCIF).
///
/// Provides data structures for PDB metadata including experiment information,
/// refinement statistics, assembly generation, and structural annotations.

// Copyright 2019 Global Phasing Ltd.
//
// Metadata from coordinate files.

#ifndef GEMMI_METADATA_HPP_
#define GEMMI_METADATA_HPP_

#include <cstdint>       // for uint8_t, uint16_t
#include <algorithm>     // for any_of
#include <string>
#include <vector>
#include "math.hpp"      // for Mat33
#include "unitcell.hpp"  // for Position, Asu
#include "seqid.hpp"     // for SeqId

namespace gemmi {

/// @brief Software used in data collection, processing, or refinement.
/// @details Corresponds to the mmCIF _software category. Includes tools from
/// any stage of data processing or structure determination pipeline.
struct SoftwareItem {
  /// Classification of software function in the pipeline.
  enum Classification {
    DataCollection,     ///< Used for X-ray/neutron/cryo-EM data acquisition
    DataExtraction,     ///< Extracted raw data into processable format
    DataProcessing,     ///< General data processing (merging, scaling, etc.)
    DataReduction,      ///< Reduced data complexity or dimensionality
    DataScaling,        ///< Scaling and merging reflection intensities
    ModelBuilding,      ///< Model construction and atom placement
    Phasing,            ///< Phasing (MAD, MR, direct methods, etc.)
    Refinement,         ///< Structure refinement
    Unspecified         ///< Purpose not classified
  };
  std::string name;                 ///< Software name
  std::string version;              ///< Version number or identifier
  std::string date;                 ///< Date of execution or release
  std::string description;          ///< Additional details
  std::string contact_author;       ///< Contact person name
  std::string contact_author_email; ///< Contact email address
  Classification classification = Unspecified; ///< Functional classification
};

/// @brief Statistics for reflection data from a single diffraction set or shell.
/// @details Information from PDB REMARK 200/230 expanded in PDBx/mmCIF.
/// Corresponds to data across mmCIF _reflns and _reflns_shell categories.
struct ReflectionsInfo {
  double resolution_high = NAN;     ///< Highest resolution limit (Ångströms)
  double resolution_low = NAN;      ///< Lowest resolution limit (Ångströms)
  double completeness = NAN;        ///< Fraction of unique reflections measured (%)
  double redundancy = NAN;          ///< Average multiplicity of measurements
  double r_merge = NAN;             ///< R_merge = Σ|I - <I>| / Σ<I> merging statistic
  double r_sym = NAN;               ///< R_sym (Rsym) intensity agreement statistic
  double mean_I_over_sigma = NAN;   ///< Average intensity / standard deviation
};

/// @brief Experimental setup and data collection method.
/// @details Corresponds to mmCIF _exptl category. Each entry usually contains
/// one experiment, except in joint refinement (e.g., X-ray + neutron).
struct ExperimentInfo {
  std::string method;                 ///< Technique: X-ray, neutron, electron, synchrotron, etc.
  int number_of_crystals = -1;        ///< Number of crystals used in data collection
  int unique_reflections = -1;        ///< Count of unique reflections measured
  ReflectionsInfo reflections;        ///< Overall statistics for all reflections
  double b_wilson = NAN;              ///< Wilson B-factor estimate (Ų)
  std::vector<ReflectionsInfo> shells; ///< Per-resolution-shell statistics
  std::vector<std::string> diffraction_ids; ///< Associated diffraction set identifiers
};

/// @brief Details of radiation source and detector configuration.
/// @details Corresponds to mmCIF _diffrn_source and _diffrn_radiation categories.
struct DiffractionInfo {
  std::string id;                 ///< Unique identifier for this diffraction set
  double temperature = NAN;       ///< Temperature during data collection (K)
  std::string source;             ///< Radiation source (e.g., synchrotron, rotating anode)
  std::string source_type;        ///< Source type classification
  std::string synchrotron;        ///< Name/abbreviation of synchrotron facility
  std::string beamline;           ///< Beamline name/identifier
  std::string wavelengths;        ///< Wavelength(s) used (Ångströms)
  std::string scattering_type;    ///< Type of scattering (X-ray, electron, neutron)
  char mono_or_laue = '\0';       ///< 'M' for monochromatic, 'L' for Laue geometry
  std::string monochromator;      ///< Monochromator crystal and orientation
  std::string collection_date;    ///< Date of data collection
  std::string optics;             ///< Detector optics and configuration details
  std::string detector;           ///< Detector model or description
  std::string detector_make;      ///< Detector manufacturer
};

/// @brief Crystal growth conditions and associated diffraction data.
/// @details Corresponds to mmCIF _exptl_crystal and _exptl_crystal_grow categories.
struct CrystalInfo {
  std::string id;                   ///< Unique crystal identifier
  std::string description;          ///< Morphology, color, or other physical properties
  double ph = NAN;                  ///< pH of crystallization condition
  std::string ph_range;             ///< pH range if not a fixed value
  std::vector<DiffractionInfo> diffractions; ///< Diffraction data from this crystal
};


/// @brief TLS (Translation/Libration/Screw) group for rigid-body refinement.
/// @details Corresponds to mmCIF _pdbx_refine_tls category. Used to model
/// anisotropic motion of rigid domains in structure refinement.
struct TlsGroup {
  /// Residue selection for TLS group.
  struct Selection {
    std::string chain;          ///< Chain identifier
    SeqId res_begin;            ///< Starting residue sequence number
    SeqId res_end;              ///< Ending residue sequence number
    std::string details;        ///< Additional selection criteria
  };
  short num_id = -1;            ///< Numeric TLS group ID (internal optimization)
  std::string id;               ///< TLS group identifier string
  std::vector<Selection> selections; ///< Chain/residue ranges in this group
  Position origin;              ///< Origin of libration and screw axes (x, y, z)
  SMat33<double> T = {NAN, NAN, NAN, NAN, NAN, NAN}; ///< Translation tensor (Ų)
  SMat33<double> L = {NAN, NAN, NAN, NAN, NAN, NAN}; ///< Libration tensor (rotational, radians²)
  Mat33 S = Mat33{NAN};         ///< Screw rotation tensor (radians/Ångström)
};

/// @brief Refinement statistics for a resolution shell or overall data.
/// @details Statistics are reported either as overall values (in RefinementInfo)
/// or per-resolution-shell (in RefinementInfo::bins). Corresponds to mmCIF
/// _refine and _refine_ls_shell categories; also to PDB REMARK 3.
struct BasicRefinementInfo {
  double resolution_high = NAN;     ///< Highest resolution in shell (Ångströms)
  double resolution_low = NAN;      ///< Lowest resolution in shell (Ångströms)
  double completeness = NAN;        ///< Fraction of unique reflections used (%)
  int reflection_count = -1;        ///< Total reflections observed
  int work_set_count = -1;          ///< Reflections in work set (used in refinement)
  int rfree_set_count = -1;         ///< Reflections in test set (R_free calculation)
  double r_all = NAN;               ///< R-factor for all reflections
  double r_work = NAN;              ///< R-factor for work set: Σ|F_o - F_c| / Σ|F_o|
  double r_free = NAN;              ///< R-factor for test set (cross-validation)
  double cc_fo_fc_work = NAN;       ///< Correlation coefficient (F_obs vs F_calc) for work
  double cc_fo_fc_free = NAN;       ///< Correlation coefficient for test set
  double fsc_work = NAN;            ///< Fourier Shell Correlation (cryo-EM) for work set
  double fsc_free = NAN;            ///< Fourier Shell Correlation for test set
  double cc_intensity_work = NAN;   ///< Correlation of intensities for work set
  double cc_intensity_free = NAN;   ///< Correlation of intensities for test set
};

/// @brief Complete refinement statistics and model quality assessment.
/// @details Corresponds to PDB REMARK 3 and mmCIF _refine, _refine_ls_shell,
/// _refine_ls_restr, and _pdbx_refine_tls categories.
struct RefinementInfo : BasicRefinementInfo {
  /// Restraint statistics for a single restraint type.
  struct Restr {
    std::string name;        ///< Type of restraint (e.g., bond length, angle)
    int count = -1;          ///< Number of restraints of this type
    double weight = NAN;     ///< Weight applied during refinement
    std::string function;    ///< Functional form of restraint
    double dev_ideal = NAN;  ///< RMS deviation from ideal values

    Restr() = default;
    /// @brief Construct with restraint name.
    explicit Restr(const std::string& name_) : name(name_) {}
  };
  std::string id;                                  ///< Refinement identifier
  std::string cross_validation_method;             ///< Method for R-free set selection
  std::string rfree_selection_method;              ///< Details of R-free selection strategy
  int bin_count = -1;                              ///< Total number of resolution shells
  std::vector<BasicRefinementInfo> bins;           ///< Per-resolution-shell statistics
  double mean_b = NAN;                             ///< Mean B-factor of all atoms (Ų)
  SMat33<double> aniso_b{NAN,NAN,NAN,NAN,NAN,NAN}; ///< Anisotropic B-factor tensor
  double luzzati_error = NAN;                      ///< Luzzati coordinate error estimate (Å)
  double dpi_blow_r = NAN;                         ///< DPI (Blow) uncertainty for R-factor
  double dpi_blow_rfree = NAN;                     ///< DPI (Blow) uncertainty for R-free
  double dpi_cruickshank_r = NAN;                  ///< DPI (Cruickshank) uncertainty for R
  double dpi_cruickshank_rfree = NAN;              ///< DPI (Cruickshank) uncertainty for R-free
  std::vector<Restr> restr_stats;                  ///< Restraint statistics by type
  std::vector<TlsGroup> tls_groups;                ///< TLS (rigid-body) groups
  std::string remarks;                             ///< Additional refinement notes
};


/// @brief Complete metadata from a coordinate file.
/// @details Aggregates all experimental, refinement, and assembly information
/// from PDB/mmCIF header and remarks. Extracted from multiple mmCIF categories
/// and PDB REMARK records.
struct Metadata {
  std::vector<std::string> authors;        ///< Authors of the structure
  std::vector<ExperimentInfo> experiments; ///< Experimental setup (X-ray, cryo-EM, etc.)
  std::vector<CrystalInfo> crystals;       ///< Crystal and diffraction information
  std::vector<RefinementInfo> refinement;  ///< Refinement statistics and quality metrics
  std::vector<SoftwareItem> software;      ///< Software used in data processing/refinement
  std::string solved_by;                   ///< Method: X-ray, NMR, EM, theoretical model, etc.
  std::string starting_model;              ///< Starting coordinates for refinement
  std::string remark_300_detail;           ///< Details of biological assembly annotation

  /// @brief Check if any refinement entry has a non-NaN value for field.
  /// @param field Pointer-to-member for a double field in RefinementInfo.
  /// @return True if any refinement entry has a non-NaN value.
  bool has(double RefinementInfo::*field) const {
    return std::any_of(refinement.begin(), refinement.end(),
            [&](const RefinementInfo& r) { return !std::isnan(r.*field); });
  }

  /// @brief Check if any refinement entry has a non-(-1) value for field.
  /// @param field Pointer-to-member for an int field in RefinementInfo.
  /// @return True if any refinement entry has a value != -1.
  bool has(int RefinementInfo::*field) const {
    return std::any_of(refinement.begin(), refinement.end(),
            [&](const RefinementInfo& r) { return r.*field != -1; });
  }

  /// @brief Check if any refinement entry has a non-empty string value for field.
  /// @param field Pointer-to-member for a std::string field in RefinementInfo.
  /// @return True if any refinement entry has non-empty string.
  bool has(std::string RefinementInfo::*field) const {
    return std::any_of(refinement.begin(), refinement.end(),
            [&](const RefinementInfo& r) { return !(r.*field).empty(); });
  }

  /// @brief Check if any refinement entry has a non-NaN value in matrix field.
  /// @param field Pointer-to-member for SMat33<double> field in RefinementInfo.
  /// @return True if any refinement entry has u11 != NaN.
  bool has(SMat33<double> RefinementInfo::*field) const {
    return std::any_of(refinement.begin(), refinement.end(),
        [&](const RefinementInfo& r) { return !std::isnan((r.*field).u11); });
  }

  /// @brief Check if any refinement entry has restraint statistics.
  /// @return True if any refinement contains non-empty restr_stats.
  bool has_restr() const {
    return std::any_of(refinement.begin(), refinement.end(),
            [&](const RefinementInfo& r) { return !r.restr_stats.empty(); });
  }

  /// @brief Get TLS groups from refinement entries.
  /// @return Pointer to TLS group vector from first refinement with groups,
  ///         or nullptr if none found. In joint refinement, TLS groups
  ///         should be associated with only one RefinementInfo entry.
  std::vector<gemmi::TlsGroup>* get_tls_groups() {
    for (gemmi::RefinementInfo& ref : refinement)
      if (!ref.tls_groups.empty())
        return &ref.tls_groups;
    return nullptr;
  }

  /// @brief Get TLS groups from refinement entries (const version).
  /// @return Pointer to TLS group vector or nullptr if none found.
  const std::vector<gemmi::TlsGroup>* get_tls_groups() const {
    return const_cast<Metadata*>(this)->get_tls_groups();
  }
};


/// @brief Classification of macromolecular entities, corresponding to mmCIF _entity.type.
/// @details Classifies biological units by macromolecular type.
enum class EntityType : unsigned char {
  Unknown,    ///< Type not specified or cannot be determined
  Polymer,    ///< Protein, nucleic acid, or polysaccharide
  NonPolymer, ///< Small organic or inorganic molecule
  Branched,   ///< Branched polymer (introduced in mmCIF 2020)
  Water       ///< Water, heavy water, or aqueous solvent
};

/// @brief Polymer classification by chemical type.
/// @details Corresponds to mmCIF _entity_poly.type. Numbers in comments indicate
/// approximate counts in PDB as of 2017-2020.
enum class PolymerType : unsigned char {
  Unknown,              ///< Unknown polymer type or not applicable (~0)
  PeptideL,             ///< L-amino acid polymer polypeptide(L) (~168k entries)
  PeptideD,             ///< D-amino acid polymer polypeptide(D) (~57 entries)
  Dna,                  ///< DNA polydeoxyribonucleotide (~9.9k entries)
  Rna,                  ///< RNA polyribonucleotide (~4.6k entries)
  DnaRnaHybrid,         ///< DNA-RNA hybrid (~156 entries)
  SaccharideD,          ///< D-polysaccharide (~18 entries)
  SaccharideL,          ///< L-polysaccharide (~0 entries)
  Pna,                  ///< Peptide nucleic acid (~2 entries)
  CyclicPseudoPeptide,  ///< Cyclic pseudo-peptide (~1 entry)
  Other,                ///< Other polymer types (~4 entries)
};

/// @brief Check if polymer is a polypeptide (L or D form).
inline bool is_polypeptide(PolymerType pt) {
  return pt == PolymerType::PeptideL || pt == PolymerType::PeptideD;
}

/// @brief Check if polymer is a nucleic acid (DNA, RNA, or hybrid).
inline bool is_polynucleotide(PolymerType pt) {
  return pt == PolymerType::Dna || pt == PolymerType::Rna ||
         pt == PolymerType::DnaRnaHybrid;
}

/// @brief Description of a macromolecular entity in the structure.
/// @details Corresponds to mmCIF _entity category. Contains polymer type,
/// database cross-references, and sequence information.
struct Entity {
  /// Cross-reference to external database (UniProt, GenBank, etc.).
  struct DbRef {
    std::string db_name;              ///< Database name (UNIPROT, GENBANK, PIR, etc.)
    std::string accession_code;       ///< Database accession/ID
    std::string id_code;              ///< Database sequence code
    std::string isoform;              ///< Isoform identifier if applicable
    SeqId seq_begin, seq_end;         ///< PDB sequence number range
    SeqId db_begin, db_end;           ///< Database sequence number range
    SeqId::OptionalNum label_seq_begin, label_seq_end; ///< mmCIF label_seq_id range
  };
  std::string name;                        ///< Entity name/description
  std::vector<std::string> subchains;      ///< Chains in this entity
  EntityType entity_type = EntityType::Unknown;     ///< Macromolecular type
  PolymerType polymer_type = PolymerType::Unknown;  ///< Polymer classification
  bool reflects_microhetero = false;       ///< True if sequence reflects microheterogeneity
  std::vector<DbRef> dbrefs;               ///< Cross-references to external databases
  std::vector<std::string> sifts_unp_acc;  ///< UniProt accessions (SIFTS mapping)
  std::vector<std::string> full_sequence;  ///< SEQRES/entity_poly_seq with microhetero

  Entity() = default;
  /// @brief Construct with entity name.
  explicit Entity(const std::string& name_) noexcept : name(name_) {}

  /// @brief Extract first component from comma-separated monomer list.
  /// @param mon_list Space-separated monomer names (may contain commas for hetero).
  /// @return Monomer name up to first comma, or entire string if no comma.
  static std::string first_mon(const std::string& mon_list) {
    return mon_list.substr(0, mon_list.find(','));
  }
};

/// @brief Reference to a UniProt residue via SIFTS mapping.
/// @details Maps PDB residue to UniProt sequence. Used in Residue::sifts_unp.
/// Corresponds to mmCIF _pdbx_sifts_xref_db category.
struct SiftsUnpResidue {
  char res = '\0';             ///< UniProt residue one-letter code ('\0' = unset)
  std::uint8_t acc_index = 0;  ///< Index into Entity::sifts_unp_acc array
  std::uint16_t num = 0;       ///< UniProt sequence position (0 = unset)
};

/// @brief A chemical connection (bond) between two atoms in the structure.
///
/// Corresponds to mmCIF _struct_conn records. The type field indicates the
/// nature of the bond (covalent, hydrogen, metal coordination, etc.).
struct Connection {
  /// Type of chemical interaction.
  enum Type : unsigned char {
    Covale = 0,  ///< Covalent bond (including disulfides before classification)
    Disulf,      ///< Disulfide bridge (S-S)
    Hydrog,      ///< Hydrogen bond
    MetalC,      ///< Metal coordination
    Unknown      ///< Unclassified or unknown type
  };
  std::string name;            ///< Connection identifier
  std::string link_id;         ///< Reference to chemical link definition
  Type type = Unknown;         ///< Classification of interaction
  Asu asu = Asu::Any;          ///< Asymmetric unit relationship
  AtomAddress partner1, partner2; ///< Two atoms in the connection
  double reported_distance = 0.0; ///< Distance from coordinate file (Ångströms)
  short reported_sym[4] = {};  ///< Symmetry operator (for internal use, unreliable)
};

/// @brief Cis peptide bond annotation.
/// @details Corresponds to PDB CISPEP record or mmCIF _struct_mon_prot_cis.
struct CisPep {
  AtomAddress partner_c;       ///< C-terminal carbonyl carbon
  AtomAddress partner_n;       ///< N-terminal amide nitrogen
  int model_num = 0;           ///< Model number (if per-model specificity)
  char only_altloc = '\0';     ///< Alternate location (if specific conformation)
  double reported_angle = NAN; ///< Omega dihedral angle (degrees)
};

/// @brief Modified residue annotation.
/// @details Records post-translational or in-situ modifications.
/// Corresponds to PDB MODRES record or mmCIF _pdbx_mod_residue_detail.
struct ModRes {
  std::string chain_name;      ///< Chain containing modified residue
  ResidueId res_id;            ///< Position of modified residue
  std::string parent_comp_id;  ///< Unmodified residue type (standard 3-letter code)
  std::string mod_id;          ///< Modified residue code
  std::string details;         ///< Description of modification
};

/// @brief Binding, catalytic, or functional site annotation.
/// @details Corresponds to PDB SITE record or mmCIF _struct_site category.
/// Annotates regions important for function.
struct StructSite {
  /// Residue or atom participating in the site.
  struct Member {
    int residue_num = -1;        ///< Residue count in site
    std::string label_comp_id;   ///< mmCIF component (residue) name
    std::string label_asym_id;   ///< mmCIF chain identifier
    SeqId::OptionalNum label_seq;///< mmCIF sequence number
    std::string label_atom_id;   ///< mmCIF atom name
    char label_alt_id = '\0';    ///< Alternate location code
    AtomAddress auth;            ///< PDB-style atom address
    std::string symmetry;        ///< Symmetry operator applied
    std::string details;         ///< Role or functional description
  };
  std::string name;              ///< Site identifier/name
  std::string evidence_code;     ///< Evidence classification
  AtomAddress residue;           ///< Representative residue
  int residue_count = -1;        ///< Total residues in site
  std::string details;           ///< Site description
  std::vector<Member> members;   ///< Atoms/residues comprising site

  StructSite() = default;
  /// @brief Construct with site name.
  explicit StructSite(const std::string& name_) noexcept : name(name_) {}
};

/// @brief Protein secondary structure: alpha helix or similar.
/// @details Corresponds to PDB HELIX record or mmCIF _struct_conf category.
/// As of 2019, almost exclusively right-handed alpha helix (type 1) or
/// 3-10 helix (type 5) in the PDB (~99% of ~4M helix annotations).
struct Helix {
  /// Helix type classification from PDB HELIX records.
  enum HelixClass {
    UnknownHelix = 0, ///< Unspecified helix type
    RAlpha = 1,       ///< Right-handed alpha helix (~3.6 res/turn)
    ROmega = 2,       ///< Right-handed omega helix (rare)
    RPi = 3,          ///< Right-handed pi helix (rare)
    RGamma = 4,       ///< Right-handed gamma helix (rare)
    R310 = 5,         ///< Right-handed 3-10 helix (~3 res/turn)
    LAlpha = 6,       ///< Left-handed alpha helix (rare)
    LOmega = 7,       ///< Left-handed omega helix (rare)
    LGamma = 8,       ///< Left-handed gamma helix (rare)
    Helix27 = 9,      ///< 2-7 ribbon/helix (rare)
    HelixPolyProlineNone = 10 ///< Polyproline helix (rare)
  };
  AtomAddress start;              ///< First residue of helix
  AtomAddress end;                ///< Last residue of helix
  HelixClass pdb_helix_class = UnknownHelix; ///< Helix type
  int length = -1;                ///< Number of residues in helix

  /// @brief Set helix class from integer code (1-10).
  void set_helix_class_as_int(int n) {
    if (n >= 1 && n <= 10)
      pdb_helix_class = static_cast<HelixClass>(n);
  }
};

/// @brief Beta sheet secondary structure.
/// @details Corresponds to PDB SHEET record or mmCIF _struct_sheet category.
struct Sheet {
  /// Individual beta strand in a sheet.
  struct Strand {
    AtomAddress start;       ///< First residue of strand
    AtomAddress end;         ///< Last residue of strand
    AtomAddress hbond_atom2; ///< H-bond donor atom (previous strand)
    AtomAddress hbond_atom1; ///< H-bond acceptor atom (current strand)
    int sense;               ///< 0=first strand, 1=parallel, -1=anti-parallel
    std::string name;        ///< Strand identifier (mmCIF only)
  };
  std::string name;                ///< Sheet identifier
  std::vector<Strand> strands;     ///< Strands in this sheet

  Sheet() = default;
  /// @brief Construct with sheet ID.
  explicit Sheet(const std::string& sheet_id) noexcept : name(sheet_id) {}
};


/// @brief Biological assembly (macromolecular complex).
/// @details Corresponds to PDB REMARK 350 or mmCIF _pdbx_struct_assembly.
/// Describes how asymmetric unit chains are assembled into biologically
/// relevant oligomers.
struct Assembly {
  /// Rotation/translation operator for assembly generation.
  struct Operator {
    std::string name;      ///< Operator identifier (e.g., "1_555")
    std::string type;      ///< Classification (e.g., "identity", "symmetry")
    Transform transform;   ///< 3D rotation and translation
  };
  /// Generation rule combining chains with operators.
  struct Gen {
    std::vector<std::string> chains;     ///< Asymmetric unit chain IDs
    std::vector<std::string> subchains;  ///< Subchain identifiers
    std::vector<Operator> operators;     ///< Symmetry operators to apply
  };
  /// Special symmetry classification for NCS/point groups.
  enum class SpecialKind : unsigned char {
    NA = 0,               ///< No special symmetry (generic assembly)
    CompleteIcosahedral,  ///< Complete icosahedral (60 copies)
    RepresentativeHelical,///< Representative helix (not complete)
    CompletePoint         ///< Complete point group assembly
  };
  std::string name;                     ///< Assembly ID/name
  bool author_determined = false;       ///< True if determined by structure authors
  bool software_determined = false;     ///< True if determined computationally
  SpecialKind special_kind = SpecialKind::NA; ///< Special symmetry type
  int oligomeric_count = 0;             ///< Stoichiometry (copies in assembly)
  std::string oligomeric_details;       ///< Stoichiometry description
  std::string software_name;            ///< Software used to determine assembly
  double absa = NAN;                    ///< Buried surface area (Ų)
  double ssa = NAN;                     ///< Surface area of complex (Ų)
  double more = NAN;                    ///< Solvent free energy change (kcal/mol)
  std::vector<Gen> generators;          ///< Assembly generation rules

  Assembly() = default;
  /// @brief Construct with assembly name.
  explicit Assembly(const std::string& name_) : name(name_) {}
};

} // namespace gemmi
#endif
