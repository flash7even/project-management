import requests

data = [
["CREATE_ATTENDANCE", "Create Attendance Log", "ATTENDANCE"],

["CREATE_PROJECT", "Create Project", "PROJECT"],
["DELETE_PROJECT", "Delete Project", "PROJECT"],
["UPDATE_PROJECT", "Update Project Details", "PROJECT"],
["SEARCH_PROJECT", "Search Project Entry", "PROJECT"],
["VIEW_PROJECT", "View Project Details", "PROJECT"],

["CREATE_BILL", "Create Bill", "BILL"],
["DELETE_BILL", "Delete Bill", "BILL"],
["UPDATE_BILL", "Update Bill Details", "BILL"],
["SEARCH_BILL", "Search Bill Entry", "BILL"],
["VIEW_BILL", "View Bill Details", "BILL"],

["CREATE_LOOKUP", "Create Lookup Entry", "LOOKUP"],
["DELETE_LOOKUP", "Delete Lookup", "LOOKUP"],
["UPDATE_LOOKUP", "Update Lookup Details", "LOOKUP"],
["SEARCH_LOOKUP", "Search Lookup Entry", "LOOKUP"],
["VIEW_LOOKUP", "View Lookup Details", "LOOKUP"],

["CREATE_USER", "Create User", "USER"],
["DELETE_USER", "Delete User", "USER"],
["UPDATE_USER", "Update User Details", "USER"],
["SEARCH_USER", "Search User Entry", "USER"],
["VIEW_USER", "View User Details", "USER"],

["ALL", "ALL", "GLOBAL"],
["NONE", "NONE", "GLOBAL"],
["DEPRECATED", "DEPRECATED", "GLOBAL"]
]

host_name = "localhost:9200"
_es_index = "pms_method_access_lookup"
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