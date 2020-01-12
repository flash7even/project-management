import requests

data = [
["CREATE_ATTENDANCE", "Create Attendance Log", "ATTENDANCE"],

["CREATE_DEVICE", "Create Device", "DEVICE"],
["DELETE_DEVICE", "Delete Device", "DEVICE"],
["UPDATE_DEVICE", "Update Device Details", "DEVICE"],
["SEARCH_DEVICE", "Search Device Entry", "DEVICE"],
["VIEW_DEVICE", "View Device Details", "DEVICE"],

["CREATE_DOOR", "Create Door", "DOOR"],
["DELETE_DOOR", "Delete Door", "DOOR"],
["UPDATE_DOOR", "Update Door Details", "DOOR"],
["SEARCH_DOOR", "Search Door Entry", "DOOR"],
["VIEW_DOOR", "View Door Details", "DOOR"],

["SEARCH_FACE", "Search FRS Matching", "FRS"],
["ENROLL_FACE", "Enroll Image Face", "FRS"],

["UPLOAD_FILE", "Upload File", "FILES"],
["DOWNLOAD_FILE", "Download File", "FILES"],

["CREATE_LOOKUP", "Create Lookup Entry", "LOOKUP"],
["DELETE_LOOKUP", "Delete Lookup", "LOOKUP"],
["UPDATE_LOOKUP", "Update Lookup Details", "LOOKUP"],
["SEARCH_LOOKUP", "Search Lookup Entry", "LOOKUP"],
["VIEW_LOOKUP", "View Lookup Details", "LOOKUP"],

["CREATE_GUEST", "Create Guest", "GUEST"],
["DELETE_GUEST", "Delete Guest", "GUEST"],
["UPDATE_GUEST", "Update Guest Details", "GUEST"],
["SEARCH_GUEST", "Search Guest Entry", "GUEST"],
["VIEW_GUEST", "View Guest Details", "GUEST"],

["UPDATE_APPOINTMENT", "Update Appointment Details", "APPOINTMENT"],
["SEARCH_APPOINTMENT", "Search Appointment Entry", "APPOINTMENT"],
["DELETE_APPOINTMENT", "Delete Appointment", "APPOINTMENT"],
["CREATE_APPOINTMENT", "Create Appointment", "APPOINTMENT"],

["CREATE_USER", "Create User", "USER"],
["DELETE_USER", "Delete User", "USER"],
["UPDATE_USER", "Update User Details", "USER"],
["SEARCH_USER", "Search User Entry", "USER"],
["VIEW_USER", "View User Details", "USER"],

["ALL", "ALL", "GLOBAL"],
["NONE", "NONE", "GLOBAL"],
["DEPRECATED", "DEPRECATED", "GLOBAL"]
]

host_name = "192.168.5.127:9200"
_es_index = "tardy_method_access_lookup"
_es_type = "access"
_http_headers = {'Content-Type': 'application/json'}
rs = requests.session()
post_url = 'http://{}/{}/{}'.format(host_name, _es_index, _es_type)

for mdata in data:
    jsdata = {
        'access_code': mdata[0],
        'access_name': mdata[1],
        'access_group': mdata[2]
    }
    response = rs.post(url=post_url, json=jsdata, headers=_http_headers).json()
    print(response)
    if 'created' not in response or response['created'] is False:
        print('ERROR: ', mdata)
    else:
        print('Successful')
print('Done')