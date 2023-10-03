# Get all route of a swagger file json  

import json
import sys
import argparse
import traceback
import requests
import urllib3
import urllib.parse
from web import Request
from prance import ResolvingParser

AUTOFILL_VALUES = {
    "file": ("pix.gif", b"GIF89a", "image/gif"),
    "integer": "1337",
    "string": "default",
    "time": "13:37",
    "url": "https://wapiti-scanner.github.io/",
    "boolean": "true",
    "object": {},
}

def get_base_url(swaggerFile, url):
    try:
        if 'schemes' not in swaggerFile:
            # get http or https from url
            swaggerFile['schemes'] = urllib.parse.urlparse(url).scheme
        if 'host' not in swaggerFile:
            if url:
                swaggerFile['host'] = urllib.parse.urlparse(url).hostname
            else:
                swaggerFile['host'] = ""
        elif swaggerFile['host'] == "localhost" and url:
            swaggerFile['host'] = urllib.parse.urlparse(url).hostname
        if 'basePath' not in swaggerFile:
            swaggerFile['basePath'] = ""
        if 'https' in swaggerFile['schemes']:
            return 'https://' + swaggerFile['host'] + swaggerFile['basePath']
        else:
            return 'http://' + swaggerFile['host'] + swaggerFile['basePath']
    except ValueError as e:
        raise Exception("[-] Error: Swagger file is not valid\n" + str(e) + "\nSee https://swagger.io/specification/ for more information")


def check_properties(model_name):
    if "properties" in model_name:
        return model_name['properties']
    elif "additionalProperties" in model_name:
        return model_name['additionalProperties']
    else:
        return model_name


def parse_object(model_name):
    try:
        model = {}
        #print(swaggerFile[swagerModel][model_name]['properties'])
        for key in model_name:
            if 'type' in model_name[key]:
                if 'object' in model_name[key]['type']:
                    ref = check_properties(model_name[key])
                    model[key] = parse_object(ref)
                    if 'type' in model[key]:
                        if model[key]['type'] == "array":
                            model[key] = {"array": model[key]['items']}
                        else:
                            model[key] = model[key]['type']
                elif 'array' in model_name[key]['type']:
                    if 'type' in model_name[key]['items']:
                        model[key] = {"array": model_name[key]['items']['type']}
                        if 'object' in model_name[key]['items']['type']:
                            ref = check_properties(model_name[key]['items'])
                            model[key]["array"] = parse_object(ref)          
                else:
                    model[key] = model_name[key]['type']
            else:
                model[key] = model_name[key]
        return model
    except ValueError as e:
        raise Exception("[-] Error: Swagger file is not valid\n" + str(e) + "\nSee https://swagger.io/specification/ for more information")


def get_routes(swaggerFile, url):
    try:
        request = {}
        
        base_path = get_base_url(swaggerFile, url)
        for path in swaggerFile['paths']:
            for method in swaggerFile['paths'][path]:
                route = method.upper() + " " + base_path + path
                params = get_parameters(swaggerFile, route, url)
                request[route] = []
                # get only in and type parameters
                if params:
                    request_route = {"method": method.upper(), "route": route.replace(method.upper() + ' ', '')}
                    request_route['params'] = []
                    for param in params:
                        raw = {}
                        if 'in' in param:
                            raw['in'] = param['in']
                            if param['in'] == "body" and 'schema' in param:
                                if 'type' in param['schema']:
                                    if 'object' in param['schema']['type']:
                                        ref = check_properties(param['schema'])
                                        model = parse_object(ref)
                                        raw['model'] = model
                                    elif 'array' in param['schema']['type']:
                                        if 'object' in param['schema']['items']['type']:
                                            ref = check_properties(param['schema']['items'])
                                            model = parse_object(ref)
                                            raw['model'] = model
                                    else:
                                        raw['type'] = param['schema']['type']
                        if 'type' in param:
                            if param['type'] == "array":
                                if 'enum' in param['items']:
                                    raw['type'] = {"enum" : param['items']['enum']}
                                else:
                                    raw['type'] = {"array" : param['items']['type']}
                            else:
                                raw['type'] = param['type']
                        if 'name' in param:
                            raw['name'] = param['name']
                        if 'required' in param:
                            raw['required'] = param['required']
                        if raw != {}:
                            request_route['params'].append(raw)
                    request[route].append(request_route)
                else:
                    request_route = {"method": method.upper(), "route": route.replace(method.upper() + ' ', '')}
                    request[route].append(request_route)
        return request 
    except Exception as e:
        print(traceback.print_exc())
        print("[-] Error: " + str(e))
        sys.exit(1)


# Get parameters from a route
def get_parameters(swaggerFile, route, url):
    try:
        base_path = get_base_url(swaggerFile, url)
        route = route.replace(base_path, '')
        method = route.split(' ')[0].lower()
        route = route.replace(method.upper() + ' ', '')
        for path in swaggerFile['paths']:
            if route == path:
                return swaggerFile['paths'][path][method]['parameters']
    except KeyError as e:
        return None
    except Exception as e:
        print(traceback.print_exc())
        print("[-] Error: " + str(e))
        sys.exit(1)


# transform dict {array: something} and if something is a dict and contains {array: something} transform it 
def transform_array(array):
    if 'array' in array:
        if isinstance(array['array'], dict):
            array = [transform_array(array['array'])]
        else:
            array = [AUTOFILL_VALUES[array['array']]]
    else:
        for key in array:
            if isinstance(array[key], dict):
                array[key] = transform_array(array[key])
            elif 'array' in array[key]:
                array[key] = [AUTOFILL_VALUES[array[key]['array']]]
            else:
                array[key] = AUTOFILL_VALUES[array[key]]
    return array


# create request with default value from swagger file
def create_request(routes):
    for route in routes:
        url = routes[route][0]['route']
        data = ""
        header = {}
        option = ""
        files = []
        if 'params' in routes[route][0]:
            for param in routes[route][0]['params']:
                if 'in' in param:
                    if param['in'] == "path":
                        url = url.replace("{" + param['name'] + "}", AUTOFILL_VALUES[param['type']])
                    elif param['in'] == "query":
                        if '?' in routes[route][0]['route'] or '?' in option:
                            option += "&" + param['name'] + "="
                        else:
                            option += "?" + param['name'] + "="
                        if 'enum' in param['type']:
                            option += param['type']['enum'][0]
                        elif 'array' in param['type']:
                            option += AUTOFILL_VALUES[param['type']['array']]
                        else:
                            option += AUTOFILL_VALUES[param['type']]
                    elif param['in'] == "body":
                        if 'model' in param:
                            json_dict = {}
                            for key in param['model']:
                                if 'array' in param['model'][key]:
                                    json_dict[key] = transform_array(param['model'][key])
                                elif isinstance(param['model'][key], dict):
                                    json_dict[key] = replace_param(param['model'][key])
                                else:
                                    json_dict[key] = AUTOFILL_VALUES[param['model'][key]]
                            data = json.dumps(json_dict)
                    elif param['in'] == "formData":
                        if 'enum' in param['type']:
                            data = add_data(data, param['name'], param['type']['enum'][0])
                        elif 'array' in param['type']:
                            data = add_data(data, param['name'], "[" + AUTOFILL_VALUES[param['type']['array']] + "]")
                        else:
                            if param['type'] == "file":
                                files.append(AUTOFILL_VALUES[param['type']])
                            else:
                                data = add_data(data, param['name'], AUTOFILL_VALUES[param['type']])
                    elif param['in'] == "header":
                        header[param['name']] = AUTOFILL_VALUES[param['type']]
            print()
        print(url + option)
        print("METHOD = " + routes[route][0]['method'])
        print("data = " + str(data))
        print("header = " + str(header))
        print("files = " + str(files))
        print()
        Request(url + option, routes[route][0]['method'], data, header, files)


def add_data(data, name, value):
    if data != "":
        data += "&" + name + "=" + value
    else:
        data += name + "=" + value
    return data


def replace_param(json_dict):
    if 'array' in json_dict:
        if isinstance(json_dict['array'], dict):
            json_dict = [replace_param(json_dict['array'])]
        else:
            json_dict = [AUTOFILL_VALUES[json_dict['array']]]
    else:
        for key in json_dict:
            if isinstance(json_dict[key], dict):
                replace_param(json_dict[key])
            elif 'array' in json_dict[key]:
                json_dict[key] = [AUTOFILL_VALUES[json_dict[key]['array']]]
            else:
                json_dict[key] = AUTOFILL_VALUES[json_dict[key]]
    return json_dict    


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('-u', '--url', help='Swagger URL')
        args = parser.parse_args()

        if args.url:
            swaggerFile = ResolvingParser(args.url, backend='openapi-spec-validator').specification
        else:
            print("[-] Error: No URL or file")
            sys.exit(1)

        routes = get_routes(swaggerFile, args.url)
        #print(json.dumps(routes, indent=4, sort_keys=True))
        create_request(routes)
    except Exception as e:
        print(traceback.print_exc())
        print("[-] Error: " + str(e))
        sys.exit(1)