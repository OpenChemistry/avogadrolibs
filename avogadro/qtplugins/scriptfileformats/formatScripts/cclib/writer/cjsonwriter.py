# This file is part of cclib (http://cclib.github.io), a library for parsing
# and interpreting the results of computational chemistry packages.
#
# Copyright (C) 2014-2016, the cclib development team
#
# The library is free software, distributed under the terms of
# the GNU Lesser General Public version 2.1 or later. You should have
# received a copy of the license along with cclib. You can also access
# the full license online at http://www.gnu.org/copyleft/lgpl.html.

"""A writer for chemical JSON (CJSON) files."""

try:
    import openbabel as ob
    has_openbabel = True
except ImportError:
    has_openbabel = False

import json
import ntpath
import numpy as np
import os.path

from . import filewriter
from cclib.parser import ccData


class CJSON(filewriter.Writer):
    """A writer for chemical JSON (CJSON) files."""
    
    def __init__(self, ccdata, terse=False, *args, **kwargs):
        """Initialize the chemical JSON writer object.

        Inputs:
          ccdata - An instance of ccData, parsed from a logfile.
        """

        # Call the __init__ method of the superclass
        super(CJSON, self).__init__(ccdata, terse=terse, *args, **kwargs)

    def pathname(self, path):
        """
        This function is OS independent and returns the file name irrespective of
        the file path containing forward slash or backward slash - which is valid
        in Windows
        """
        head, tail = ntpath.split(path)
        return tail or ntpath.basename(head)

    def generate_repr(self):
        """Generate the CJSON representation of the logfile data"""

        cjson_dict = dict()
        
        # Need to decide on a number format
        cjson_dict['chemical json'] = 0
        if self.jobfilename is not None:
            cjson_dict['name'] = self.pathname(os.path.splitext(self.jobfilename)[0])

        # These are properties that can be collected using Open Babel.
        if has_openbabel:
            cjson_dict['smiles'] = self.pbmol.write('smiles')
            cjson_dict['inchi'] = self.pbmol.write('inchi')
            cjson_dict['inchikey'] = self.pbmol.write('inchikey')
            cjson_dict['formula'] = self.pbmol.formula
            
        # Incorporate Unit Cell into the chemical JSON

        # Helpers functions which use properties provided by cclib
        self.generate_properties(cjson_dict)
        self.generate_atoms(cjson_dict)
        self.generate_optimization(cjson_dict)
        self.generate_vibrations(cjson_dict)
        self.generate_bonds(cjson_dict)
        self.generate_transitions(cjson_dict)
        self.generate_fragments(cjson_dict)

        if has_openbabel:
            cjson_dict['diagram'] = self.pbmol.write(format='svg')

        if self.terse:
            return json.dumps(cjson_dict, cls=NumpyAwareJSONEncoder)
        else:
            return json.dumps(cjson_dict, cls=JSONIndentEncoder, sort_keys=True, indent=4)

    def set_JSON_attribute(self, object, list):
        """
        Args:
            object: Python dictionary which is being appended with the key value
            list: list of cclib attribute name

        Returns: 
            None. The dictionary is modified to contain the attribute with the
                 cclib keyname as key
        """
        for key in list:
            if hasattr(self.ccdata, key):
                object[ccData._attributes[key].jsonKey] = getattr(self.ccdata, key)

    def has_data(self, attr_names):
        """
        Args:
            attr_names: Python List containing cclib attribute names

        Returns: 
            Boolean True/False. Returns true if atleast one attribute in the list exists in the output file                 
        """ 
        for name in attr_names:
            if hasattr(self.ccdata, name):
                return True
        return False
        
    def generate_properties(self, cjson_dict):
        """ Appends the Properties object into the cjson
        Properties table:
            1) Molecular Mass
            2) Charge
            3) Multiplicity
            4) Energy
                 i) alpha
                     a) homo
                     b) gap
                 ii) beta        
                     a) homo
                     b) gap
                iii) Total       
                 iv) Free Energy 
                  v) Moller - Plesset 
                 vi) Coupled Cluster 
            5) Enthalpy 
            6) Entropy 
            7) numberOfAtoms    
            8) Temperature 
            9) totalDipoleMoment 
            10) Partial Charges
                 i) Mulliken 
            11) Orbitals 
                 i) Homos   
                ii) Energies  
               iii) Overlaps 
                iv) Symmetry 
                 v) Coeffs
        """
        cjson_dict['properties'] = dict()
        
        if has_openbabel:
            cjson_dict['properties']['molecular mass'] = self.pbmol.molwt
            
        self.set_JSON_attribute(cjson_dict['properties'], ['charge', 'mult'])
        
        energy_attr = ['moenergies', 'freeenergy', 'mpenergies', 'ccenergies']
        if self.has_data(energy_attr):
            cjson_dict['properties']['energy'] = dict()
            
            if hasattr(self.ccdata, 'moenergies') and hasattr(self.ccdata, 'homos'):
                cjson_dict['properties']['energy']['alpha'] = dict()
                cjson_dict['properties']['energy']['beta'] = dict()
                
                homo_idx_alpha = int(self.ccdata.homos[0])
                homo_idx_beta = int(self.ccdata.homos[-1])
                energy_alpha_homo = self.ccdata.moenergies[0][homo_idx_alpha]
                energy_alpha_lumo = self.ccdata.moenergies[0][homo_idx_alpha + 1]
                energy_alpha_gap = energy_alpha_lumo - energy_alpha_homo
                energy_beta_homo = self.ccdata.moenergies[-1][homo_idx_beta]
                energy_beta_lumo = self.ccdata.moenergies[-1][homo_idx_beta + 1]
                energy_beta_gap = energy_beta_lumo - energy_beta_homo
                
                cjson_dict['properties']['energy']['alpha']['homo'] = energy_alpha_homo
                cjson_dict['properties']['energy']['alpha']['gap'] = energy_alpha_gap
                cjson_dict['properties']['energy']['beta']['homo'] = energy_beta_homo
                cjson_dict['properties']['energy']['beta']['gap'] = energy_beta_gap
                cjson_dict['properties']['energy']['total'] = self.ccdata.scfenergies[-1]

            self.set_JSON_attribute(cjson_dict['properties']['energy'], ['freeenergy', 'mpenergies', 'ccenergies'])

        self.set_JSON_attribute(cjson_dict['properties'], ['enthalpy', 'entropy', 'natom', 'temperature'])

        if hasattr(self.ccdata, 'moments'):
            cjson_dict['properties'][ccData._attributes['moments'].jsonKey] = self._calculate_total_dipole_moment()

        if hasattr(self.ccdata, 'atomcharges'):
            cjson_dict['properties']['partial charges'] = dict()
            cjson_dict['properties']['partial charges'] = self.ccdata.atomcharges
        
        orbital_attr = ['homos', 'moenergies', 'aooverlaps', 'mosyms', 'mocoeffs']
        if self.has_data(orbital_attr):
            cjson_dict['properties']['orbitals'] = dict()
            self.set_JSON_attribute(cjson_dict['properties']['orbitals'], orbital_attr)

    def generate_atoms(self, cjson_dict):
        """ Appends the Atoms object into the cjson
        Atoms Table:
            1) Elements
                a) Number
                b) atomCount                
                c) heavyAtomCount                
            2) Coords
                a) 3d                    
            3) Orbitals
                a) Names
                b) Indices
            4) Coreelectrons
            5) Mass
            6) Spins
        """
        cjson_dict['atoms'] = dict()
        
        if hasattr(self.ccdata, 'atomnos'):
            cjson_dict['atoms']['elements'] = dict()
            cjson_dict['atoms']['elements'][ccData._attributes['atomnos'].jsonKey] = self.ccdata.atomnos
            cjson_dict['atoms']['elements']['atom count'] = len(self.ccdata.atomnos)
            cjson_dict['atoms']['elements']['heavy atom count'] = len([x for x in self.ccdata.atomnos if x > 1])
        
        if hasattr(self.ccdata, 'atomcoords'):
            cjson_dict['atoms']['coords'] = dict()
            cjson_dict['atoms']['coords']['3d'] = self.ccdata.atomcoords[-1].flatten().tolist()
            
        orbital_list = ['aonames', 'atombasis']
        if self.has_data(orbital_list):
            cjson_dict['atoms']['orbitals'] = dict()
            self.set_JSON_attribute(cjson_dict['atoms']['orbitals'], orbital_list)

        self.set_JSON_attribute(cjson_dict['atoms'], ['coreelectrons', 'atommasses', 'atomspins'])

    def generate_optimization(self, cjson_dict):
        """ Appends the Optimization object into the cjson
            Optimization table:
                1) Done 
                2) Status  
                3) Geometric Targets 
                4) Geometric Values 
                5) Basis number 
                6) MO number 
                7) SCF 
                    a) Energies 
                    b) Targets 
                    c) Values 
                8) Scan 
                    a) Step Geometry 
                    b) Potential Energy Surface - energies     
                    c) Variable names 
                    d) PES Parameter Values 
        """
        opti_attr = ['optdone', 'geotargets', 'nbasis', 'nmo', 'scfenergies', 'scancoords', 'scannames']
        if self.has_data(opti_attr):
            cjson_dict['optimization'] = dict()
            attr_list = ['optdone', 'optstatus', 'geotargets', 'geovalues', 'nbasis', 'nmo']
            self.set_JSON_attribute(cjson_dict['optimization'], attr_list)

            # assumption: If SCFenergies exist, then scftargets will also exist
            if hasattr(self.ccdata, 'scfenergies') or hasattr(self.ccdata, 'scfvalues'):
                cjson_dict['optimization']['scf'] = dict()
                attr_list = ['scfenergies', 'scftargets', 'scfvalues']
                self.set_JSON_attribute(cjson_dict['optimization']['scf'], attr_list)
                
            # Similar assumption as above
            if hasattr(self.ccdata, 'scanenergies'):
                cjson_dict['optimization']['scan'] = dict()
                attr_list = ['scancoords', 'scanenergies', 'scannames', 'scanparm']
                self.set_JSON_attribute(cjson_dict['optimization']['scan'], attr_list)
                
    def generate_vibrations(self, cjson_dict):
        """ Appends the Vibrations object into the cjson
            Vibrations table:
                1) Anharmonicity constants 
                2) Frequencies  
                3) Symmetry 
                4) Hessian matrix 
                5) Displacement 
                6) Intensities 
                    a)IR 
                    b) Raman               
        """
        vib_attr = ['vibanharms', 'vibanharms', 'vibirs', 'vibramans', 'vibsyms', 'hessian', 'vibdisps']
        if self.has_data(vib_attr):
            cjson_dict['vibrations'] = dict()
            
            attr_list = ['vibanharms', 'vibfreqs', 'vibsyms', 'hessian', 'vibdisps']
            self.set_JSON_attribute(cjson_dict['vibrations'], attr_list)
            
            if hasattr(self.ccdata, 'vibirs') or hasattr(self.ccdata, 'vibramans'):
                cjson_dict['vibrations']['intensities'] = dict()
                attr_list = ['vibirs', 'vibramans']
                self.set_JSON_attribute(cjson_dict['vibrations']['intensities'], attr_list)
            
    def generate_bonds(self, cjson_dict):
        """ Appends the Bonds object into the cjson
            Bonds table:
                1) Connections 
                    a) Index
                2) Order    
        """
        if has_openbabel and (len(self.ccdata.atomnos) > 1):
            cjson_dict['bonds'] = dict()
            cjson_dict['bonds']['connections'] = dict()
            cjson_dict['bonds']['connections']['index'] = []
            for bond in self.bond_connectivities:
                cjson_dict['bonds']['connections']['index'].append(bond[0] + 1)
                cjson_dict['bonds']['connections']['index'].append(bond[1] + 1)
            cjson_dict['bonds']['order'] = [bond[2] for bond in self.bond_connectivities]
            
    def generate_transitions(self, cjson_dict):
        """ Appends the Transition object into the cjson
            Transitions table:
               1) Electronic Transitions 
               2) Oscillator Strength 
               3) Rotatory Strength 
               4) 1-excited-config  
               5) Symmetry 
        """
        attr_list = ['etenergies', 'etoscs', 'etrotats', 'etsecs', 'etsyms']
        if self.has_data(attr_list):
            cjson_dict['transitions'] = dict()
            self.set_JSON_attribute(cjson_dict['transitions'], attr_list)
                
    def generate_fragments(self, cjson_dict):
        """ Appends the Fragments object into the cjson
            Fragments table:
               1) Names 
               2) Atom Indices 
               3) Orbital Names 
               4) Orbital Overlap 
        """
        attr_list = ['fragnames', 'frags', 'fonames', 'fooverlaps']
        if self.has_data(attr_list):
            cjson_dict['fragments'] = dict()
            self.set_JSON_attribute(cjson_dict['fragments'], attr_list)


class NumpyAwareJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.ndarray):
            if obj.ndim == 1:
                return obj.tolist()
            else:
                return [self.default(obj[i]) for i in range(obj.shape[0])]
        return json.JSONEncoder.default(self, obj)


class JSONIndentEncoder(json.JSONEncoder):
    def __init__(self, *args, **kwargs):
        super(JSONIndentEncoder, self).__init__(*args, **kwargs)
        self.current_indent = 0
        self.current_indent_str = ""

    def encode(self, o):
        # Special Processing for lists
        if isinstance(o, (list, tuple)):
            primitives_only = True
            for item in o:
                if isinstance(item, (list, tuple, dict)):
                    primitives_only = False
                    break
            output = []
            if primitives_only:
                for item in o:
                    output.append(json.dumps(item,  cls=NumpyAwareJSONEncoder))
                return "[ " + ", ".join(output) + " ]"
            else:
                self.current_indent += self.indent
                self.current_indent_str = "".join([" " for x in range(self.current_indent)])
                for item in o:
                    output.append(self.current_indent_str + self.encode(item))
                self.current_indent -= self.indent
                self.current_indent_str = "".join([" " for x in range(self.current_indent)])
                return "[\n" + ",\n".join(output) + "\n" + self.current_indent_str + "]"
        elif isinstance(o, dict):
            output = []
            self.current_indent += self.indent
            self.current_indent_str = "".join([" " for x in range(self.current_indent)])
            for key, value in o.items():
                output.append(self.current_indent_str + json.dumps(key, cls=NumpyAwareJSONEncoder) + ": " +
                              str(self.encode(value)))
            self.current_indent -= self.indent
            self.current_indent_str = "".join([" " for x in range(self.current_indent)])
            return "{\n" + ",\n".join(output) + "\n" + self.current_indent_str + "}"
        else:
            return json.dumps(o, cls=NumpyAwareJSONEncoder)


if __name__ == "__main__":
    pass
