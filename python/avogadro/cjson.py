"""
/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the New BSD License, (the "License").
******************************************************************************/
"""
import json
class Cjson:
    """
    This Class is intended to read Cjson files
    with python libraries and perform certain
    methods on files and convert them back to Cjson
    files as required
    """
    def __init__(self):
        pass
    def __open_file(self, filePath):
        '''Use to read CJson formats by converting them to python dictionaries'''
        with open(filePath, 'r') as cjsonFile:
            py_dict_data = json.load(cjsonFile)
            return py_dict_data
    def __to_cjson(self, cjson_dict_file):
        '''It converts python dictionaries to CJson format'''
        cjsonData = json.dumps(cjson_dict_file, indent=4)
        return (cjsonData)
    def get_atoms_coords(self,filePath):
        """
        It helps to get the co-ordinates of individual elements/atoms in the format
        [
            x co-ordinate
            y co-ordinate
            z co-ordinate
            Atomic Number of Element
        ]
        """
        data = self.__open_file(filePath)
        coords = data["atoms"]["coords"]["3d"]
        elements = data["atoms"]["elements"]["number"]
        element_coords = [(*coords[i*3:(i+1)*3], elements[i]) for i in range(0, int(len(coords) / 3))]
        cjson_dict = {"element-coordinates" :element_coords}
        return self.__to_cjson(cjson_dict)

    def get_elements(self, filePath):
        data = self.__open_file(filePath)
        elements = data["atoms"]["elements"]["number"]
        return elements