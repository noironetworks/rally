from rally import consts
from rally import exceptions
from rally.common import validation
from rally.aci_plugins import vcpe_utils
from rally.aci_plugins import create_ostack_resources
from rally.plugins.openstack import scenario
from rally.plugins.openstack.scenarios.nova import utils as nova_utils
from rally.plugins.openstack.scenarios.neutron import utils as neutron_utils
import time
import uuid
import re
import json

from openstackclient.tests.functional.network.v2 import common

@validation.add("required_services", services=[consts.Service.NOVA, consts.Service.NEUTRON])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(name="ScenarioPlugin.address_group", context={"cleanup@openstack": ["nova", "neutron"],
                             "keypair@openstack": {},
                             "allow_ssh@openstack": None}, platform="openstack")

class AddressGroup(create_ostack_resources.CreateOstackResources, vcpe_utils.vCPEScenario, neutron_utils.NeutronScenario,
                         nova_utils.NovaScenario, scenario.OpenStackScenario, common.NetworkTests):

    def run(self, cidr1, cidr2, access_network, nat_network, aci_nodes, image, flavor, username, password, dualstack):

        try:
            net1 = self._create_network({"provider:network_type": "vlan"})
            sub1 = self._create_subnet(net1, {"cidr": cidr1},  None)
            net2 = self._create_network({"provider:network_type": "vlan"})
            sub2 = self._create_subnet(net2, {"cidr": cidr2},  None)

            print( "\n Networks created - net1 and net2 \n")

            router = self._create_router({}, False)

            print( "\n Router created \n")
            
            self._add_interface_router(sub1['subnet'], router.get("router"))
            self._add_interface_router(sub2['subnet'], router.get("router"))

            SG_NAME = uuid.uuid4().hex
            sg = self.create_security_group(SG_NAME)

            print( "\n Security Group created \n")

            key_name=self.context["user"]["keypair"]["name"]
            port_create_args = {}
            port_create_args["security_groups"] = [sg['security_group']['id']]
             
            pfip11 = self._create_port(net1, port_create_args)
            vm11 = self.boot_vm(pfip11.get('port', {}).get('id'), image, flavor, key_name=key_name)
            pfip12 = self._create_port(net1, port_create_args)
            vm12 = self.boot_vm(pfip12.get('port', {}).get('id'), image, flavor, key_name=key_name)
            self.sleep_between(50, 60)


            print( "\n vms created on net1 \n")

            SG_NAME = uuid.uuid4().hex
            sg1 = self.create_security_group(SG_NAME)

            print( "\n Security Group created \n")

            port_create_args = {}
            port_create_args["security_groups"] = [sg['security_group']['id'], sg1['security_group']['id']]

            public_network = self.clients("neutron").show_network(access_network)
            pfip2_1, pfip2_1_id = self.create_port(public_network, port_create_args)

            pfip2 = self._create_port(net2, port_create_args)
            vm2 = self.boot_vm([pfip2_1_id, pfip2.get('port', {}).get('id')], image, flavor, key_name=key_name)
            self.sleep_between(90, 100)

            print( "\n vm created on net2 \n")

            fip11 = [pfip11.get('port', {}).get(
                'fixed_ips')[0].get('ip_address')]
            fip12 = [pfip12.get('port', {}).get(
                'fixed_ips')[0].get('ip_address')]
            fip2_1 = [pfip2_1.get('port', {}).get(
                'fixed_ips')[0].get('ip_address')]
            fip2 = [pfip2.get('port', {}).get(
                'fixed_ips')[0].get('ip_address')]
            
            AG_NAME = uuid.uuid4().hex
            ag = self.openstack(
                'address group create '
                + '--description aaaa '
                + '--address '+ fip11[0] +' --address '+ fip12[0] + ' --address '+ fip2[0] + ' ' 
                + AG_NAME,
                cloud='',
            )

            print( "\n Address Group created with address of net1 vms and net2 vm\n")
            
            lines = ag.split('\n')
            id_line = [line for line in lines if '| id ' in line]
            ag_id = id_line[0].split('|')[-2].strip()
            
            self.create_security_group_rule(sg_id=sg1['security_group']['id'], protocol=None,direction="ingress", ethertype="IPv4", remote_group_id=sg1['security_group']['id'], remote_address_group_id=None,remote_ip_prefix=None)
            self.create_security_group_rule(sg_id=sg1['security_group']['id'], protocol="icmp",direction="ingress", ethertype="IPv4", remote_group_id=None, remote_address_group_id=None,remote_ip_prefix="0.0.0.0/0")
            self.create_security_group_rule(sg_id=sg1['security_group']['id'], protocol=None,direction="ingress", ethertype="IPv6", remote_group_id=sg1['security_group']['id'], remote_address_group_id=None,remote_ip_prefix=None)
            self.create_security_group_rule(sg_id=sg1['security_group']['id'], protocol="tcp",direction="ingress", ethertype="IPv4", remote_group_id=None, remote_address_group_id=None,remote_ip_prefix="0.0.0.0/0")
            
            print( "\n security group rules created to access vms from rally \n")

            command = {"interpreter": "/bin/sh", "script_inline": "ping -c 5 " + fip11[0]}
            print( "\n validating ping between net1 and net2 vms without address group rule \n")
            
            self._remote_command_wo_server("root","noir0123", fip2_1[0], command)
            self.create_security_group_rule(sg_id=sg['security_group']['id'], protocol="icmp", direction="ingress", ethertype="IPv4", remote_group_id=None, remote_address_group_id=ag_id, remote_ip_prefix=None)
            
            print( "\n security group rule created with above address group \n")
            print( "\n validating ping between net1 and net2 vms with address group rule \n")
            self.sleep_between(20,30)
            self._remote_command_validate("root","noir0123", fip2_1[0], command)            

        except AssertionError as msg:
            raise msg
        
                
