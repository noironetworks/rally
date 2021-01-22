import yaml
import json
import sys

filename = sys.argv[1]
dictionary = {"image": "img", "flavor": "flv", "dual_stack": False, "extrtr_net1": "extrtr_net1"}

yaml_data = yaml.safe_load(open(filename))
for keys, values in yaml_data.items():
    if 'controller_ip' in keys:
        dictionary["controller_ip"] = yaml_data["controller_ip"]
    if 'primary_L3out' in keys:
        dictionary['L3OUT1'] = yaml_data["primary_L3out"]
    if 'primary_L3out_net' in keys:
        dictionary["L3OUT1_NET"] = yaml_data["primary_L3out_net"]
    if 'primary_L3out_vrf' in keys:
        dictionary["L3OUT1_VRF"] = yaml_data["primary_L3out_vrf"]
    if 'secondary_L3out' in keys:
        dictionary["L3OUT2"] = yaml_data["secondary_L3out"]
    if 'secondary_L3out_net' in keys:
        dictionary["L3OUT2_NET"] = yaml_data["secondary_L3out_net"]
    if 'secondary_L3out_vrf' in keys:
        dictionary["L3OUT2_VRF"] = yaml_data["secondary_L3out_vrf"]
    if 'ext_rtr' in keys:
        dictionary["ext_rtr"] = yaml_data["ext_rtr"]
    if 'extrtr_ip1' in keys:
        dictionary["extrtr_ip1"] = yaml_data["extrtr_ip1"]
    if 'extrtr_ip2' in keys:
        dictionary["extrtr_ip2"] = yaml_data["extrtr_ip2"]
    if 'gwip1_extrtr' in keys:
        dictionary["gwip1_extrtr"] = yaml_data["gwip1_extrtr"]
    if 'gwip2_extrtr' in keys:
        dictionary["gwip2_extrtr"] = yaml_data["gwip2_extrtr"]
    if 'nova_az_name' in keys:
        dictionary["nova_az"] = yaml_data["nova_az_name"]
    if 'plugin-type' in keys:
        dictionary["plugin_type"] = yaml_data["plugin-type"]
    if 'dual_stack' in keys:
        dictionary["dual_stack"] = yaml_data["dual_stack"]
    if 'extrtr_net1' in dictionary.keys():
        dictionary["extrtr_net1"] = yaml_data["extrtr_ip1"][:-1]+"0/24"

json_data = json.dumps(dictionary, indent=4)
with open("args.json", "w") as outfile:
    outfile.write(json_data)



