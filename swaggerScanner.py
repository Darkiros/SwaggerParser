# Get all route of a swagger file json  

import json
import sys
import argparse
import traceback
import requests
import urllib3
import urllib.parse
from web import Request

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
        if 'basePath' not in swaggerFile:
            swaggerFile['basePath'] = ""
        if 'https' in swaggerFile['schemes']:
            return 'https://' + swaggerFile['host'] + swaggerFile['basePath']
        else:
            return 'http://' + swaggerFile['host'] + swaggerFile['basePath']
    except ValueError as e:
        raise Exception("[-] Error: Swagger file is not valid\n" + str(e) + "\nSee https://swagger.io/specification/ for more information")


def get_swagger_file(url):
    try:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = requests.get(url, verify=False)     
        if response.status_code == 200:
            if "application/json" in response.headers['Content-Type']:
                response = response.json()
            return response
        else:
            print("[-] Error: " + str(response.status_code))
            sys.exit(1)
    except Exception as e:
        print(traceback.print_exc())
        print("[-] Error: " + str(e))
        sys.exit(1)


def get_swagger_file_local(file):
    try:
        with open(file, 'r') as stream:
            if file.split('.')[-1] == "json":
                return json.load(stream)
    except Exception as e:
        print("[-] Error: " + str(e))
        sys.exit(1)


def get_model(swaggerFile, model_name, ref):
    try:
        model = {}
        swagerModel = ref.split('/')[-1]
        if model_name in swaggerFile[swagerModel]:
            if 'properties' in swaggerFile[swagerModel][model_name]:
                #print(swaggerFile[swagerModel][model_name]['properties'])
                for key in swaggerFile[swagerModel][model_name]['properties']:
                    if '$ref' in swaggerFile[swagerModel][model_name]['properties'][key]:
                        ref = swaggerFile[swagerModel][model_name]['properties'][key]['$ref'].split('/')
                        refModel = ref[-1]
                        ref.pop()
                        ref = '/'.join(ref)
                        model[key] = get_model(swaggerFile, refModel, ref)
                    elif 'array' in swaggerFile[swagerModel][model_name]['properties'][key]['type']:
                        if 'type' in swaggerFile[swagerModel][model_name]['properties'][key]['items']:
                            model[key] = {"array": swaggerFile[swagerModel][model_name]['properties'][key]['items']['type']}
                        elif '$ref' in swaggerFile[swagerModel][model_name]['properties'][key]['items']:
                            ref = swaggerFile[swagerModel][model_name]['properties'][key]['items']['$ref'].split('/')
                            refModel = ref[-1]
                            ref.pop()
                            ref = '/'.join(ref)
                            model[key] = get_model(swaggerFile, refModel, ref)
                    else:
                        model[key] = swaggerFile[swagerModel][model_name]['properties'][key]['type']
            else:
                #print(swaggerFile[swagerModel][model_name])
                pass

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
                            if param['in'] == "body":
                                # Get model
                                if 'schema' in param:
                                    if '$ref' in param['schema']:
                                        ref = param['schema']['$ref']
                                        raw['model'] = ref.split('/')[-1]
                                        ref = ref.split('/')
                                        ref.pop()
                                        ref = '/'.join(ref)
                                        model = get_model(swaggerFile, raw['model'], ref)
                                        raw['model'] = model
                                    elif 'items' in param['schema']:
                                        if '$ref' in param['schema']['items']:
                                            ref = param['schema']['items']['$ref']
                                            raw['model'] = ref.split('/')[-1]
                                            ref = ref.split('/')
                                            ref.pop()
                                            ref = '/'.join(ref)
                                            model = get_model(swaggerFile, raw['model'], ref)
                                            raw['model'] = model
                                    if 'type' in param['schema']:
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
                        if '$ref' in param:
                            ref = param['$ref']
                            raw['model'] = ref.split('/')[-1]
                            ref = ref.split('/')
                            ref.pop()
                            ref = '/'.join(ref)
                            model = get_model(swaggerFile, raw['model'], ref)
                            raw['model'] = model
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
                        url = routes[route][0]['route'].replace("{" + param['name'] + "}", AUTOFILL_VALUES[param['type']])
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
                                if isinstance(param['model'][key], dict):
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

        print(url + option)
        print("METHOD = " + routes[route][0]['method'])
        print("data = " + str(data))
        print("header = " + str(header))
        print("files = " + str(files))
        print()
        Request(url + option, routes[route][0]['method'], data, header, files)
        #requete = Request(routes[route][0][route], routes[route][0]['method'])

def add_data(data, name, value):
    if data != "":
        data += "&" + name + "=" + value
    else:
        data += name + "=" + value
    return data


def replace_param(json_dict):
    if 'array' in json_dict:
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
        parser.add_argument('-f', '--file', help='Swagger file')
        args = parser.parse_args()

        if args.url:
            swaggerFile = get_swagger_file(args.url)
            url = args.url
        elif args.file:
            swaggerFile = get_swagger_file_local(args.file)
            url = None
        else:
            print("[-] Error: No URL or file")
            sys.exit(1)

        routes = get_routes(swaggerFile, url)
        #print(json.dumps(routes, indent=4, sort_keys=True))
        create_request(routes)
    except Exception as e:
        print(traceback.print_exc())
        print("[-] Error: " + str(e))
        sys.exit(1)