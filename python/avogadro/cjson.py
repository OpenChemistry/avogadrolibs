"""
/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-clause BSD License, (the "License").
******************************************************************************/
"""
import json


class cjson:
    """
    This class is intended to read and write cjson (chemical json) files
    and help manipulate them (e.g., change coordinates, elements, etc.)

    The cjson format is a JSON format for chemical information. It is
    intended to be a common exchange and storage format for chemical
    information that is both human and machine readable. It is intended
    to be easily extended to support new features and data types.

    More information and the schema can be found at:
    https://github.com/OpenChemistry/chemicaljson
    """

    def __init__(self):
        pass

    def __from_cjson(self, filePath):
        """Use to read cjson formats by converting them to python dictionaries"""
        with open(filePath, "r") as cjsonFile:
            py_dict_data = json.load(cjsonFile)
            return py_dict_data

    def __to_cjson(self, cjson_dict_file):
        """It converts python dictionaries to cjson format"""
        cjsonData = json.dumps(cjson_dict_file, indent=4)
        return cjsonData

    def get_atoms_coords(self, filePath):
        """
        It helps to get the co-ordinates of individual elements/atoms in the format
        [
            x co-ordinate
            y co-ordinate
            z co-ordinate
            Atomic Number of Element
        ]
        """
        data = self.__from_cjson(filePath)
        coords = data["atoms"]["coords"]["3d"]
        elements = data["atoms"]["elements"]["number"]
        element_coords = [
            (*coords[i * 3 : (i + 1) * 3], elements[i])
            for i in range(0, int(len(coords) / 3))
        ]
        cjson_dict = {"element-coordinates": element_coords}
        return self.__to_cjson(cjson_dict)

    def get_elements(self, filePath):
        """
        returns all the elements present in cjson file
        """
        data = self.__from_cjson(filePath)
        elements = data["atoms"]["elements"]["number"]
        return elements

    def get_coordinates(self, filePath):
        """
        returns the coordinate array
        """
        data = self.__from_cjson(filePath)
        coords = data["atoms"]["coords"]["3d"]
        return coords

    def set_atoms_coordinates(self, filePath, coords_array):
        """
        it updates the coordinates array in cjson file
        """
        data = self.__from_cjson(filePath)
        data["atoms"]["coords"]["3d"] = coords_array
        return self.__to_cjson(data)

    def set_elements(self, filePath, elements_array):
        """
        It sets all the elements present in the cjson file
        where elements are set/recognized by their atomic numbers
        """
        data = self.__from_cjson(filePath)
        data["atoms"]["elements"]["number"] = elements_array
        return self.__to_cjson(data)

    def set_coordinates(self, filePath, coords_array):
        """
        It helps to set all coordinates of the
        cjson file where coordinates of all elements
        can be changed by an input array of coords_array
        """
        data = self.__from_cjson(filePath)
        data["atoms"]["coords"]["3d"] = coords_array
        return self.__to_cjson(data)
