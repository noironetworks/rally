from rally import consts
from rally.common import validation
from rally.noirotest_framework import create_resources
from rally.noirotest_framework import gbputils
from rally.plugins.openstack import scenario
from rally.noirotest_framework import osutils
from rally.plugins.openstack.scenarios.neutron import utils as neutron_utils
from rally.plugins.openstack.scenarios.nova import utils as nova_utils


@validation.add("required_services", services=[consts.Service.NOVA, consts.Service.NEUTRON])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(name="ScenarioPlugin.ml2_sanity", context={"cleanup@openstack": ["nova", "neutron"]},
                    platform="openstack")
class ML2Sanity(neutron_utils.NeutronScenario, gbputils.GBPScenario, osutils.OSScenario, nova_utils.NovaScenario,
                scenario.OpenStackScenario, create_resources.CreateResources):

    def run(self, image, flavor):
        dual_stack = False
        print("Creating project PENGUIN and creating resources in it")
        pro1 = self._create_project('PENGUIN', 'default')
        user1 = self._create_user('penguin', 'noir0123', pro1.id, "default", True, "Admin")
        dic = self.context
        new_user = dic.get("users")[0]
        new_user.get("credential").update({'username': 'penguin', 'tenant_name': 'penguin', 'password': 'noir0123'})
        self.context.get("users").append(new_user)
        self._change_client(1, self.context, None, None)

        secgroup1 = self.context.get("user", {}).get("secgroup")
        key_name1 = self.context["user"]["keypair"]["name"]

        net1, sub1 = self._create_network_and_subnets({}, {"cidr": '11.11.11.0/28'}, 1, None)
        sub_list1 = [sub1[0]]
        if dual_stack:
            sub1v6 = self._create_subnet(net1, {"cidr": "2001:db8:1::/64", "ipv6_ra_mode": "slaac",
                                                "ipv6_address_mode": "slaac"}, None)
            sub_list1.append(sub1v6)
        net2, sub2 = self._create_network_and_subnets({}, {"cidr": '21.21.21.0/28'}, 1, None)
        sub_list1.append(sub2[0])
        if dual_stack:
            sub2v6 = self._create_subnet(net2, {"cidr": "2001:db8:2::/64", "ipv6_ra_mode": "slaac",
                                                "ipv6_address_mode": "slaac"}, None)
            sub_list1.append(sub2v6)

        router1 = self._create_router({}, False)
        self._add_interface_router(sub1[0].get("subnet"), router1.get("router"))
        self._add_interface_router(sub2[0].get("subnet"), router1.get("router"))
        if dual_stack:
            self._add_interface_router(sub1v6.get("subnet"), router1.get("router"))
            self._add_interface_router(sub2v6.get("subnet"), router1.get("router"))

        ext_net1 = self._admin_create_network('L3OUT1', {"shared": True, "router": True,
                                                         "apic:distinguished_names": {"type": "dict",
                                                                                      "ExternalNetwork": "uni/tn-common/out-Management-Out/instP-data_ext_pol"}})
        ext_sub1 = self._admin_create_subnet(ext_net1, {"cidr": '50.50.50.0/28', "no_dhcp": True}, None)
        ext_sub2 = self._admin_create_subnet(ext_net1,
                                             {"cidr": '55.55.55.0/28', "no_dhcp": True, "apic:snat_host_pool": True},
                                             None)

        self._add_gateway_router(router1, ext_net1)

        self.install_secgroup_rules(secgroup1)
        self.install_secgroup_rules(secgroup1, "::/0")
        port_create_args = {"security_groups": [secgroup1.get("security_group").get('id')]}
        p1 = self._create_port(net1, port_create_args)
        p1_id = p1.get('port', {}).get('id')
        vm1 = self.boot_server(p1_id, key_name1, image, flavor)

        p2 = self._create_port(net2, port_create_args)
        p2_id = p2.get('port', {}).get('id')
        vm2 = self.boot_server(p2_id, key_name1, image, flavor)
        #################################################################
        # traffic verification ml2
        ##########################################################

        ##################################################################
        # traffic verification ml2 with SNAT
        ##############################################################

        fip1 = self._attach_floating_ip(vm1, ext_net1)
        fip2 = self._attach_floating_ip(vm2, ext_net1)
        self.sleep_between(10, 15)
        ##########################################################
        # traffic verification ml2 with fip to ext-router
        #####################################################

        ######################################################
        # traffic verification from ext-router to fip
        ###############################################

        print("Creating project OCTON and creating resources in it")
        pro2 = self._create_project('OCTON', 'default')
        user2 = self._create_user('octon', 'noir0123', pro2.id, "default", True, "Admin")
        dic = self.context
        new_user = dic.get("users")[0]
        new_user.get("credential").update({'username': 'octon', 'tenant_name': 'octon', 'password': 'noir0123'})
        self.context.get("users").append(new_user)
        self._change_client(2, self.context, None, None)

        secgroup2 = self.context.get("user", {}).get("secgroup")
        key_name2 = self.context["user"]["keypair"]["name"]

        asc1 = self.create_address_scope("asc1", "4", False)
        if dual_stack:
            asc1v6 = self.create_address_scope("asc1v6", "6", False, **{"apic_vrf"})
        subpool1 = self.create_subnet_pool("subpool1", asc1.id, "22.22.22.0/24", "28", False)
        if dual_stack:
            subpool1v6 = self.create_subnet_pool("subpool1v6", asc1v6.id, "2001:db8:3::/56", "64", False)

        net3 = self._create_network({})
        sub3 = self._create_subnet(net3, {"subnet_pool": subpool1.id, "ip_version": "4"}, None)
        sub_list2 = [sub3]
        if dual_stack:
            sub3v6 = self._create_subnet(net3,
                                         {"subnet_pool": subpool1v6.id, "ip_version": "6", "ipv6_ra_mode": "slaac",
                                          "ipv6_address_mode": "slaac"}, None)
            sub_list2.append(sub3v6)
        net4 = self._create_network({})
        sub4 = self._create_subnet(net4, {"subnet_pool": subpool1.id, "ip_version": "4"}, None)
        sub_list2.append(sub4)
        if dual_stack:
            sub4v6 = self._create_subnet(net4,
                                         {"subnet_pool": subpool1v6.id, "ip_version": "6", "ipv6_ra_mode": "slaac",
                                          "ipv6_address_mode": "slaac"}, None)
            sub_list2.append(sub4v6)

        router2 = self._create_router({}, False)

        self.install_secgroup_rules(secgroup2)
        self.install_secgroup_rules(secgroup2, "::/0")
        port_create_args = {"security_groups": [secgroup2.get("security_group").get('id')]}
        p3 = self._create_port(net3, port_create_args)
        p3_id = p3.get('port', {}).get('id')
        vm3 = self.boot_server(p3_id, key_name2, image, flavor)

        p4 = self._create_port(net4, port_create_args)
        p4_id = p4.get('port', {}).get('id')
        vm4 = self.boot_server(p4_id, key_name2, image, flavor)

        #############################################################
        # traffic verification ml2
        #########################################################
        self._add_interface_router(sub3.get("subnet"), router2.get("router"))
        self._add_interface_router(sub4.get("subnet"), router2.get("router"))
        if dual_stack:
            self._add_interface_router(sub3v6.get("subnet"), router2.get("router"))
            self._add_interface_router(sub4v6.get("subnet"), router2.get("router"))

        if dual_stack:
            self._reboot_server(vm3)
            self._reboot_server(vm4)
        self.sleep_between(10, 15)
        ##########################################################
        # traffic verification ml2
        ########################################################

        self._add_gateway_router(router2, ext_net1)
        self.sleep_between(10, 15)

        #################################################
        # traffic verification ml2 using SNAT
        ##########################################
        fip3 = self._attach_floating_ip(vm3, ext_net1)
        fip4 = self._attach_floating_ip(vm4, ext_net1)
        self.sleep_between(10, 15)

        ###############################################
        # traffic verification using fip to ext-router
        ####################################################

        ################################################
        # traffic verification from ext-router to fip
        #############################################

        print("Creating project GARTH and creating resources in it")
        pro3 = self._create_project('GARTH', 'default')
        user3 = self._create_user('garth', 'noir0123', pro3.id, "default", True, "Admin")
        dic = self.context
        new_user = dic.get("users")[0]
        new_user.get("credential").update({'username': 'garth', 'tenant_name': 'garth', 'password': 'noir0123'})
        self.context.get("users").append(new_user)
        self._change_client(3, self.context, None, None)

        secgroup3 = self.context.get("user", {}).get("secgroup")
        key_name3 = self.context["user"]["keypair"]["name"]

        router3 = self._create_router({}, False)

        ascs = self.create_address_scope("ascs", "4", True, **{
            "apic:distinguished_names": {"type": "dict", "VRF": "uni/tn-common/ctx-l3out_2_vrf"}})
        if dual_stack:
            ascsv6 = self.create_address_scope("ascsv6", "6", True, **{
                "apic:distinguished_names": {"type": "dict", "VRF": "uni/tn-common/ctx-l3out_2_vrf"}})
        sps = self.create_subnet_pool("sps", ascs.id, "60.60.60.0/24", "28", True)
        if dual_stack:
            spsv6 = self.create_subnet_pool("spsv6", ascsv6.id, "2001:db8::/56", "64", True)

        net5 = self._create_network({})
        sub5 = self._create_subnet(net5, {"subnet_pool": sps.id, "ip_version": "4"}, None)
        sub_list3 = [sub5]
        if dual_stack:
            sub5v6 = self._create_subnet(net5, {"subnet_pool": spsv6.id, "ip_version": "6", "ipv6_ra_mode": "slaac",
                                                "ipv6_address_mode": "slaac"}, None)
            sub_list3.append(sub5v6)
        net6 = self._create_network({})
        sub6 = self._create_subnet(net6, {"subnet_pool": sps.id, "ip_version": "4"}, None)
        sub_list3.append(sub6)
        if dual_stack:
            sub6v6 = self._create_subnet(net6, {"subnet_pool": spsv6.id, "ip_version": "6", "ipv6_ra_mode": "slaac",
                                                "ipv6_address_mode": "slaac"}, None)
            sub_list3.append(sub6v6)

        self.install_secgroup_rules(secgroup3)
        self.install_secgroup_rules(secgroup3, "::/0")
        port_create_args = {"security_groups": [secgroup3.get("security_group").get('id')]}
        p5 = self._create_port(net5, port_create_args)
        p5_id = p5.get('port', {}).get('id')
        vm5 = self.boot_server(p5_id, key_name3, image, flavor)

        p6 = self._create_port(net6, port_create_args)
        p6_id = p6.get('port', {}).get('id')
        vm6 = self.boot_server(p6_id, key_name3, image, flavor)

        self._add_interface_router(sub5.get("subnet"), router3.get("router"))
        self._add_interface_router(sub6.get("subnet"), router3.get("router"))
        if dual_stack:
            self._add_interface_router(sub5v6.get("subnet"), router3.get("router"))
            self._add_interface_router(sub6v6.get("subnet"), router3.get("router"))

        ext_net2 = self._admin_create_network('L3OUT2', {"shared": True, "router": True,
                                                         "apic:distinguished_names": {"type": "dict",
                                                                                      "ExternalNetwork": "uni/tn-common/out-Datacenter-Out-Out/instP-data_ext_pol"},
                                                         "apic:nat_type": ""})
        ext_sub3 = self._admin_create_subnet(ext_net1, {"cidr": '2.3.4.0/24', "no_dhcp": True}, None)

        self._add_gateway_router(router3, ext_net2)

        if dual_stack:
            self._reboot_server(vm5)
            self._reboot_server(vm6)
        self.sleep_between(10, 15)

        #######################################################
        # traffic verification ml2
        #########################################################

        ###############################################
        # ml2 cleanup

        for item in [vm5, vm6]:
            self._delete_server(item)
        self._remove_gateway_router(router3)
        for item in sub_list3:
            self._remove_interface_router(item, router3)
        self._delete_router(router3)
        for item in [net5, net6]:
            self._delete_network(item)
        self._delete_subnet_pool(sps.id)
        self._delete_address_scope(ascs.id)
        if dual_stack:
            self._delete_subnet_pool(spsv6.id)
            self._delete_address_scope(ascsv6.id)

        self._change_client(2, self.context, None, None)
        self._delete_server_with_fip(vm3, fip3)
        self._delete_server_with_fip(vm4, fip4)
        self._remove_gateway_router(router2)
        for item in sub_list2:
            self._remove_interface_router(item, router2)
        self._delete_router(router2)
        for item in [net3, net4]:
            self._delete_network(item)
        self._delete_subnet_pool(subpool1.id)
        self._delete_address_scope(asc1.id)
        if dual_stack:
            self._delete_subnet_pool(subpool1v6.id)
            self._delete_address_scope(asc1v6.id)

        self._change_client(1, self.context, None, None)
        self._delete_server_with_fip(vm1, fip1)
        self._delete_server_with_fip(vm2, fip2)
        self._remove_gateway_router(router1)
        for item in sub_list1:
            self._remove_interface_router(item, router1)
        self._delete_router(router1)
        for item in [net1, net2]:
            self._delete_network(item)
        self._admin_delete_network(ext_net1)
        self._admin_delete_network(ext_net2)
        for item in [user1, user2, user3]:
            self._delete_user(item)
        for item in [pro1, pro2, pro3]:
            self._delete_project(item)



