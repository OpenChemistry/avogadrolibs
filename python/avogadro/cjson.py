import json
class Cjson:
    def __init__(self):
        print("cjson configured successfully start your operations")
    def __open_file(self, filePath):
        with open(filePath, 'r') as cjsonFile:
            py_dict_data = json.load(cjsonFile)
            return py_dict_data
    def __to_cjson(self, element_coords):
        cjson_dict = {"element-coordinates" :element_coords}
        cjsonData = json.dumps(cjson_dict, indent=4)
        print(cjsonData)
    def get_atoms_coords(self,filePath):
        data = self.__open_file(filePath)
        coords = data["atoms"]["coords"]["3d"]
        elements = data["atoms"]["elements"]["number"]
        element_coords = [(*coords[i*3:(i+1)*3], elements[i]) for i in range(0, int(len(coords) / 3))]
        print(type(element_coords))
        self.__to_cjson(element_coords)