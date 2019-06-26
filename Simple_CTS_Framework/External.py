import json
from DataModels import *

Json_technique_file_path = '.\\sources\\techniques.json'


def load_external_data():
    global Json_technique_file_path

    loaded_file_list = list()
    loaded_technique_list = list()
    with open(Json_technique_file_path) as json_file:
        json_data = json.load(json_file)
        # print(json_data['files'])

        for file_info in json_data['files']:
            file_path_with_extended_slash = file_info['file_path'].replace('\\', '\\\\')
            file = File(file_info['file_name'], file_path_with_extended_slash, file_info['file_type'])
            # print(file)
            loaded_file_list.append(file)

        for technique_info in json_data['techniques']:
            # technique = Technique
            pass

    return loaded_file_list, loaded_technique_list


if __name__ == "__main__":
    load_external_data()
