from rally import consts
from rally import exceptions
from rally.common import validation
from rally.plugins.openstack import scenario
from rally.noirotest_framework import osutils
from rally.plugins.openstack.scenarios.neutron import utils as neutron_utils
from rally.plugins.openstack.scenarios.nova import utils as nova_utils


@validation.add("required_services", services=[consts.Service.NOVA, consts.Service.NEUTRON])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(name="ScenarioPlugin.ml2_sanity", context={"cleanup@openstack": ["nova", "neutron"],
                                                               "keypair@openstack": {}, "allow_ssh@openstack": None}, platform="openstack")

class ML2Sanity(osutils.OSScenario, neutron_utils.NeutronScenario, nova_utils.NovaScenario,
                scenario.OpenStackScenario):

    def run(self, image, flavor, L3OUT1, L3OUT1_NET, L3OUT1_VRF, L3OUT2, L3OUT2_NET, L3OUT2_VRF, ext_rtr, extrtr_ip1, extrtr_ip2, dual_stack):

        print("\nCreate Openstack Tenant PENGUIN for ML2\n")
        pro1, user1, new_user = self.create_rally_client("PENGUIN", "penguin", self.context)
        self.context.get("users").append(new_user)
        self._change_client(1, self.context, None, None)

        secgroup1 = self.get_secgroup(pro1.id)

        print "Create Private Network & Subnet for ML2 Tenant PENGUIN\n"
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

        print "Create Router for ML2 Tenant PENGUIN\n"
        router1 = self._create_router({}, False)

        print "Create Shared External Network for ML2 Tenants\n"
        ext_net1, ext_sub1, ext_sub2 = self.create_external_network1(L3OUT1, L3OUT1_NET)

        print "WORKFLOW-1: Attaching router to networks BEFORE VM creation:Tenant PENGUIN\n"
        print "Attach Router to networks of the tenant PENGUIN\n"
        self._add_interface_router(sub1[0].get("subnet"), router1.get("router"))
        self._add_interface_router(sub2[0].get("subnet"), router1.get("router"))
        if dual_stack:
            self._add_interface_router(sub1v6.get("subnet"), router1.get("router"))
            self._add_interface_router(sub2v6.get("subnet"), router1.get("router"))

        print "Attach PENGUIN Router to the External Network\n"
        self._add_gateway_router(router1, ext_net1, True)

        print "Install VM for the Tenant PENGUIN\n"
        self.install_secgroup_rules(secgroup1)
        if dual_stack:
            self.install_secgroup_rules(secgroup1, "::/0")

        port_create_args = {"security_groups": [secgroup1.get("security_group").get('id')]}
        p1 = self._create_port(net1, port_create_args)
        p1_id = p1.get('port', {}).get('id')
        vm1 = self.boot_server(p1_id, image, flavor)

        p2 = self._create_port(net2, port_create_args)
        p2_id = p2.get('port', {}).get('id')
        vm2 = self.boot_server(p2_id, image, flavor)
        #################################################################
        # traffic verification ml2
        ##########################################################

        ##################################################################
        # traffic verification ml2 with SNAT
        ##############################################################

        print "Create & Attach FIP to VMs for the Tenant PENGUIN\n"
        fip1 = self._attach_floating_ip(vm1, ext_net1.get("network"))
        fip2 = self._attach_floating_ip(vm2, ext_net1.get("network"))
        self.sleep_between(20, 25)

        ip1 = p1.get('port', {}).get('fixed_ips')[0].get('ip_address')
        ip2 = p2.get('port', {}).get('fixed_ips')[0].get('ip_address')

        command1 = self.command_for_start_http_server()
        command2 = self.command_for_icmp_tcp_traffic(ip2)
        command3 = self.command_for_icmp_tcp_traffic(ip1)
        command4 = self.command_for_icmp_tcp_traffic(extrtr_ip1)
        command5 = self.command_for_icmp_tcp_traffic(extrtr_ip2)
        command6 = self.command_for_stop_http_server()

        print "\nSending Traffic from VM1 in ML2-tenant PENGUIN\n"
        self._remote_command("root", "noir0123", fip1["ip"], command1, vm1)
        self._remote_command("root", "noir0123", fip1["ip"], command2, vm1)
        self._remote_command("root", "noir0123", fip1["ip"], command4, vm1)
        self._remote_command("root", "noir0123", fip1["ip"], command5, vm1)
        self._remote_command("root", "noir0123", fip1["ip"], command6, vm1)

        print "Sending Traffic from VM2 in ML2-tenant PENGUIN\n"
        self._remote_command("root", "noir0123", fip2["ip"], command1, vm2)
        self._remote_command("root", "noir0123", fip2["ip"], command3, vm2)
        self._remote_command("root", "noir0123", fip2["ip"], command4, vm2)
        self._remote_command("root", "noir0123", fip2["ip"], command5, vm2)
        self._remote_command("root", "noir0123", fip2["ip"], command6, vm2)

        print "Sending ICMP/TCP Traffic from EXT-RTR to VMs\n"
        command7 = self.command_for_icmp_tcp_traffic_from_ext_rtr(fip1["ip"])
        command8 = self.command_for_icmp_tcp_traffic_from_ext_rtr(fip2["ip"])

        self._remote_command_wo_server("noiro", "noir0123", ext_rtr, command7)
        self._remote_command_wo_server("noiro", "noir0123", ext_rtr, command8)

        print "WORKFLOW-2: Attaching router to networks AFTER VM creation:Tenant OCTON\n"
        print("Create Openstack Tenant OCTON for ML2\n")
        pro2, user2, new_user = self.create_rally_client("OCTON", "octon", self.context)
        self.context.get("users").append(new_user)
        self._change_client(2, self.context, None, None)

        secgroup2 = self.get_secgroup(pro2.id)

        print "Create Address-Scope ONLY for Tenant OCTON\n"
        asc1 = self.create_address_scope("asc1", "4", False, False)
        if dual_stack:
            asc1v6 = self.create_address_scope("asc1v6", "6", False, False, **{"apic:distinguished_names": {"VRF": "uni/tn-common/ctx-"+L3OUT2_VRF}})

        print "Create SubnetPool ONLY for Tenant OCTON\n"
        subpool1 = self.create_subnet_pool("subpool1", asc1.get("address_scope")["id"], "22.22.22.0/24", "28", False, False)
        if dual_stack:
            subpool1v6 = self.create_subnet_pool("subpool1v6", asc1v6.get("address_scope")["id"], "2001:db8:3::/56", "64", False, False)

        print "Create Private Network & Subnet for ML2 Tenant OCTON\n"
        net3 = self._create_network({})
        sub3 = self.create_subnet_with_pool(net3, {"subnetpool_id": subpool1.get("subnetpool")["id"], "ip_version": "4"}, None)
        sub_list2 = [sub3]
        if dual_stack:
            sub3v6 = self.create_subnet_with_pool(net3,
                                                  {"subnetpool_id": subpool1v6.get("subnetpool")["id"], "ip_version": "6", "ipv6_ra_mode": "slaac",
                                                   "ipv6_address_mode": "slaac"}, None)
            sub_list2.append(sub3v6)
        net4 = self._create_network({})
        sub4 = self.create_subnet_with_pool(net4, {"subnetpool_id": subpool1.get("subnetpool")["id"], "ip_version": "4"}, None)
        sub_list2.append(sub4)
        if dual_stack:
            sub4v6 = self.create_subnet_with_pool(net4,
                                                  {"subnetpool_id": subpool1v6.get("subnetpool")["id"], "ip_version": "6", "ipv6_ra_mode": "slaac",
                                                   "ipv6_address_mode": "slaac"}, None)
            sub_list2.append(sub4v6)

        print "Create Router for ML2 Tenant OCTON\n"
        router2 = self._create_router({}, False)

        self.install_secgroup_rules(secgroup2)
        if dual_stack:
            self.install_secgroup_rules(secgroup2, "::/0")

        print "Install VM for the Tenant OCTON\n"
        port_create_args = {"security_groups": [secgroup2.get("security_group").get('id')]}
        p3 = self._create_port(net3, port_create_args)
        p3_id = p3.get('port', {}).get('id')
        vm3 = self.boot_server(p3_id, image, flavor)

        p4 = self._create_port(net4, port_create_args)
        p4_id = p4.get('port', {}).get('id')
        vm4 = self.boot_server(p4_id, image, flavor)

        #############################################################
        # traffic verification ml2
        #########################################################

        print "Attach Router to networks of the tenant OCTON\n"
        self._add_interface_router(sub3.get("subnet"), router2.get("router"))
        self._add_interface_router(sub4.get("subnet"), router2.get("router"))
        if dual_stack:
            self._add_interface_router(sub3v6.get("subnet"), router2.get("router"))
            self._add_interface_router(sub4v6.get("subnet"), router2.get("router"))
            self._reboot_server(vm3)
            self._reboot_server(vm4)
        self.sleep_between(10, 15)
        ##########################################################
        # traffic verification ml2
        ########################################################

        print "Attach OCTON Router to the External Network\n"
        self._add_gateway_router(router2, ext_net1, True)
        self.sleep_between(10, 15)

        #################################################
        # traffic verification ml2 using SNAT
        ##########################################

        print "Create & Attach FIP to VMs for the Tenant OCTON\n"
        fip3 = self._attach_floating_ip(vm3, ext_net1.get("network"))
        fip4 = self._attach_floating_ip(vm4, ext_net1.get("network"))
        self.sleep_between(10, 15)

        ip3 = p3.get('port', {}).get('fixed_ips')[0].get('ip_address')
        ip4 = p4.get('port', {}).get('fixed_ips')[0].get('ip_address')

        command9 = self.command_for_icmp_tcp_traffic(ip4)
        command10 = self.command_for_icmp_tcp_traffic(ip3)

        print "Sending Traffic from VM3 in ML2-tenant OCTON\n"
        self._remote_command("root", "noir0123", fip3["ip"], command1, vm3)
        self._remote_command("root", "noir0123", fip3["ip"], command9, vm3)
        self._remote_command("root", "noir0123", fip3["ip"], command4, vm3)
        self._remote_command("root", "noir0123", fip3["ip"], command5, vm3)
        self._remote_command("root", "noir0123", fip3["ip"], command6, vm3)

        print "Sending Traffic from VM4 in ML2-tenant OCTON\n"
        self._remote_command("root", "noir0123", fip4["ip"], command1, vm4)
        self._remote_command("root", "noir0123", fip4["ip"], command10, vm4)
        self._remote_command("root", "noir0123", fip4["ip"], command4, vm4)
        self._remote_command("root", "noir0123", fip4["ip"], command5, vm4)
        self._remote_command("root", "noir0123", fip4["ip"], command6, vm4)

        print "Sending ICMP/TCP Traffic from EXT-RTR to VMs\n"
        command11 = self.command_for_icmp_tcp_traffic_from_ext_rtr(fip3["ip"])
        command12 = self.command_for_icmp_tcp_traffic_from_ext_rtr(fip4["ip"])

        self._remote_command_wo_server("noiro", "noir0123", ext_rtr, command11)
        self._remote_command_wo_server("noiro", "noir0123", ext_rtr, command12)

        print "WORKFLOW-3: NO-NAT with Shared Address-Scope and Tenant-specific subnetpool GARTH\n"
        print("Create Openstack Tenant GARTH for ML2\n")
        pro3, user3, new_user = self.create_rally_client("GARTH", "garth", self.context)
        self.context.get("users").append(new_user)
        self._change_client(3, self.context, None, None)

        secgroup3 = self.get_secgroup(pro3.id)

        print "Create Router for ML2 Tenant GARTH\n"
        router3 = self._create_router({}, False)

        print "Create Address-Scope ONLY for Tenant admin\n"
        ascs = self.create_address_scope("ascs", "4", True, True, **{
            "apic:distinguished_names": {"VRF": "uni/tn-common/ctx-"+L3OUT2_VRF}})
        if dual_stack:
            ascsv6 = self.create_address_scope("ascsv6", "6", True, True, **{
                "apic:distinguished_names": {"VRF": "uni/tn-common/ctx-"+L3OUT2_VRF}})
        print "Create SubnetPool ONLY for Tenant GARTH\n"
        sps = self.create_subnet_pool("sps", ascs.get("address_scope")["id"], "60.60.60.0/24", "28", True, True)
        if dual_stack:
            spsv6 = self.create_subnet_pool("spsv6", ascsv6.get("address_scope")["id"], "2001:db8::/56", "64", True, True)

        print "Create Private Network & Subnet for both ML2 Tenants\n"
        net5 = self._create_network({})
        sub5 = self.create_subnet_with_pool(net5, {"subnetpool_id": sps.get("subnetpool")["id"], "ip_version": "4"}, None)
        sub_list3 = [sub5]
        if dual_stack:
            sub5v6 = self.create_subnet_with_pool(net5, {"subnetpool_id": spsv6.get("subnetpool")["id"], "ip_version": "6", "ipv6_ra_mode": "slaac",
                                                         "ipv6_address_mode": "slaac"}, None)
            sub_list3.append(sub5v6)
        net6 = self._create_network({})
        sub6 = self.create_subnet_with_pool(net6, {"subnetpool_id": sps.get("subnetpool")["id"], "ip_version": "4"}, None)
        sub_list3.append(sub6)
        if dual_stack:
            sub6v6 = self.create_subnet_with_pool(net6, {"subnetpool_id": spsv6.get("subnetpool")["id"], "ip_version": "6", "ipv6_ra_mode": "slaac",
                                                         "ipv6_address_mode": "slaac"}, None)
            sub_list3.append(sub6v6)

        print "Install VM for the Tenant GARTH\n"
        self.install_secgroup_rules(secgroup3)
        if dual_stack:
            self.install_secgroup_rules(secgroup3, "::/0")

        port_create_args = {"security_groups": [secgroup3.get("security_group").get('id')]}
        p5 = self._create_port(net5, port_create_args)
        p5_id = p5.get('port', {}).get('id')
        vm5 = self.boot_server(p5_id, image, flavor)

        p6 = self._create_port(net6, port_create_args)
        p6_id = p6.get('port', {}).get('id')
        vm6 = self.boot_server(p6_id, image, flavor)

        print "Attach Router to networks of the tenant GARTH\n"
        self._add_interface_router(sub5.get("subnet"), router3.get("router"))
        self._add_interface_router(sub6.get("subnet"), router3.get("router"))
        if dual_stack:
            self._add_interface_router(sub5v6.get("subnet"), router3.get("router"))
            self._add_interface_router(sub6v6.get("subnet"), router3.get("router"))

        print "Create Shared External Network for ML2 Tenants\n"
        ext_net2, ext_sub3 = self.create_external_network2(L3OUT2, L3OUT2_NET)

        print "Attach GARTH Router to the External Network\n"
        self._add_gateway_router(router3, ext_net2, True)

        if dual_stack:
            self._reboot_server(vm5)
            self._reboot_server(vm6)
        self.sleep_between(10, 15)

        ip5 = p5.get('port', {}).get('fixed_ips')[0].get('ip_address')
        ip6 = p6.get('port', {}).get('fixed_ips')[0].get('ip_address')

        command13 = self.command_for_icmp_tcp_traffic(ip6)
        command14 = self.command_for_icmp_tcp_traffic(ip5)
        print "Sending Traffic from VM5 in ML2-tenant GARTH\n"
        self._remote_command("root", "noir0123", ip5, command1, vm5)
        self._remote_command("root", "noir0123", ip5, command13, vm5)
        self._remote_command("root", "noir0123", ip5, command4, vm5)
        self._remote_command("root", "noir0123", ip5, command5, vm5)
        self._remote_command("root", "noir0123", ip5, command6, vm5)

        print "Sending Traffic from VM6 in ML2-tenant GARTH\n"
        self._remote_command("root", "noir0123", ip6, command1, vm6)
        self._remote_command("root", "noir0123", ip6, command14, vm6)
        self._remote_command("root", "noir0123", ip6, command4, vm6)
        self._remote_command("root", "noir0123", ip6, command5, vm6)
        self._remote_command("root", "noir0123", ip6, command6, vm6)

        print "Sending ICMP/TCP Traffic from EXT-RTR to VMs\n"
        command15 = self.command_for_icmp_tcp_traffic_from_ext_rtr(ip5)
        command16 = self.command_for_icmp_tcp_traffic_from_ext_rtr(ip6)

        self._remote_command_wo_server("noiro", "noir0123", ext_rtr, command15)
        self._remote_command_wo_server("noiro", "noir0123", ext_rtr, command16)

        print "Cleaning up setup after testing...\n"
        for item in [vm5, vm6]:
            self._delete_server(item)
        self._remove_gateway_router(router3)
        for item in sub_list3:
            self._remove_interface_router(item.get("subnet"), router3.get("router"))
        self._delete_router(router3)
        for item in [net5, net6]:
            self._delete_all_ports(item)
            self._delete_network(item.get("network"))
        self.delete_subnet_pool(sps.get("subnetpool")["id"])
        self.delete_address_scope(ascs.get("address_scope")["id"])
        if dual_stack:
            self.delete_subnet_pool(spsv6.get("subnetpool")["id"])
            self.delete_address_scope(ascsv6.get("address_scope")["id"])

        self._change_client(2, self.context, None, None)
        self._delete_floating_ip(vm3, fip3)
        self._delete_floating_ip(vm4, fip4)
        for item in [vm3, vm4]:
            self._delete_server(item)
        self._remove_gateway_router(router2)
        for item in sub_list2:
            self._remove_interface_router(item.get("subnet"), router2.get("router"))
        self._delete_router(router2)
        for item in [net3, net4]:
            self._delete_all_ports(item)
            self._delete_network(item.get("network"))
        self.delete_subnet_pool(subpool1.get("subnetpool")["id"])
        self.delete_address_scope(asc1.get("address_scope")["id"])
        if dual_stack:
            self.delete_subnet_pool(subpool1v6.get("subnetpool")["id"])
            self.delete_address_scope(asc1v6.get("address_scope")["id"])

        self._change_client(1, self.context, None, None)
        self._delete_floating_ip(vm1, fip1)
        self._delete_floating_ip(vm2, fip2)
        for item in [vm1, vm2]:
            self._delete_server(item)
        self._remove_gateway_router(router1)
        for item in sub_list1:
            self._remove_interface_router(item.get("subnet"), router1.get("router"))
        self._delete_router(router1)
        for item in [net1, net2]:
            self._delete_all_ports(item)
            self._delete_network(item.get("network"))
        self._admin_delete_network(ext_net1)
        self._admin_delete_network(ext_net2)
        for item in [user1, user2, user3]:
            self._delete_user(item)
        for item in [pro1, pro2, pro3]:
            self._delete_project(item)
