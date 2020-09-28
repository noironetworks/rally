from rally import consts
from rally import exceptions
from rally.common import validation
from rally.plugins.openstack import scenario
from rally.noirotest_framework import gbputils
from rally.noirotest_framework import osutils
from rally.noirotest_framework import create_resources
from rally.plugins.openstack.scenarios.nova import utils as nova_utils
from rally.plugins.openstack.scenarios.neutron import utils as neutron_utils

@validation.add("required_services", services=[consts.Service.NOVA, consts.Service.NEUTRON])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(name="ScenarioPlugin.north_south_test7", context={"cleanup@openstack": ["nova", "neutron"],
                    "keypair@openstack": {}, "allow_ssh@openstack": None}, platform="openstack")

class NorthSouth(create_resources.CreateResources, osutils.OSScenario, gbputils.GBPScenario, neutron_utils.NeutronScenario,
                nova_utils.NovaScenario, scenario.OpenStackScenario):

    def run(self, controller_ip, image, flavor, L3OUT1, L3OUT1_NET, L3OUT1_VRF, L3OUT2,
            L3OUT2_NET, L3OUT2_VRF, ext_rtr, extrtr_ip1, extrtr_ip2, gwip1_extrtr, nova_az, plugin_type):

        gbp = self.gbp_client(controller_ip, "admin", "noir0123", "admin")

        if plugin_type:
            ext_net_list, ext_sub_list = self.create_external_networks_subnets(L3OUT1, L3OUT1_NET, L3OUT2, L3OUT2_NET)

        policy_rule_set, policy_rules = self.create_gbp_policy_rule_set_north_south(gbp)

        print "Execution of Testcase TEST_NAT_FUNC_7 starts\n"
        print "Create External Segment "+L3OUT1+"\n"
        ext_seg = self.create_gbp_external_segment(gbp, L3OUT1,
                                                   **{"subnet_id": ext_sub_list[0].get("subnet")["id"],
                                                      "external_routes": [{"destination": "0.0.0.0/0", "nexthop": None}],
                                                      "shared": True})

        print "Create a NAT pool and associate the existing External Segment\n"
        nat_pool = self.create_gbp_nat_pool(gbp, "GbpNatPoolTest1",
                                            **{"ip_pool": "50.50.50.0/24", "external_segment_id": ext_seg})

        print "Create Policy Target group with Default L3P\n"
        ptg1 = self.create_gbp_policy_target_group(gbp, "TestPtg1")
        defaultl3p = self.verify_gbp_l3policy(gbp, "default")

        print "Create non-default L3Policy and L2Policy\n"
        l3p = self.create_gbp_l3policy(gbp, "L3PNat", **{"ip_pool": "20.20.20.0/24", "subnet_prefix_length": "26"})
        l2p = self.create_gbp_l2policy(gbp, "L2PNat", False, False, **{"l3_policy_id": l3p})

        print "Create Policy Target group with Created L3P\n"
        ptg2 = self.create_gbp_policy_target_group(gbp, "TestPtg2", **{"l2_policy_id": l2p})

        print "Associate External Segment to both L3Ps\n"
        self.update_gbp_l3policy(gbp, l3p, "uuid", **{"external_segments": ext_seg})
        self.update_gbp_l3policy(gbp, defaultl3p, "uuid", **{"external_segments": ext_seg})

        print "Create Policy Targets for each of the two PTGs\n"
        pt1, port1 = self.create_gbp_policy_target(gbp, "pt1", "TestPtg1", 1)
        pt2, port2 = self.create_gbp_policy_target(gbp, "pt2", "TestPtg2", 1)

        print "Create ExtPolicy with ExtSegment and Apply PolicyRuleSets\n"
        ext_pol = self.create_gbp_external_policy(gbp, L3OUT1_NET, **{"external_segments": [ext_seg]})

        print "Updating Policy Target Group by applying Policy RuleSets\n"
        self.update_gbp_policy_target_group(gbp, ptg1, "uuid", "", [policy_rule_set["icmp_tcp_id"]])
        self.update_gbp_policy_target_group(gbp, ptg2, "uuid", "", [policy_rule_set["icmp_tcp_id"]])

        print "Updating External Policy by applying Policy RuleSets\n"
        self.update_gbp_external_policy(gbp, ext_pol, "uuid", [policy_rule_set["icmp_tcp_id"]])

        print "Create NSP for NatPools and Associate NSP with both PTGs\n"
        nsp = self.create_gbp_network_service_policy(gbp, "TestNsp")
        self.update_gbp_policy_target_group(gbp, ptg1, "uuid", "", "", False, nsp)
        self.update_gbp_policy_target_group(gbp, ptg2, "uuid", "", "", False, nsp)

        print "Verify the Configured Objects and their Attributes\n"
        self.verify_ns_gbp_object(gbp, defaultl3p, l3p, l2p, ext_seg, "20.20.20.0/24", ext_pol, nat_pool, ptg2)

        print "Launch VMs in two diff avail-zones\n"
        vm1 = self.admin_boot_server(port1, image, flavor, "TestVM1")
        vm2 = self.admin_boot_server(port2, image, flavor, "TestVM2", **{"availability_zone": nova_az})

        self.add_route_in_extrtr(ext_rtr, "50.50.50.0/24", gwip1_extrtr, "update")

        fip1 = vm1.networks.values()[0][1]
        fip2 = vm2.networks.values()[0][1]
        print "DNATed Traffic from ExtRTR to VMs\nICMP and TCP traffic from external router\n"
        command1 = self.command_for_icmp_tcp_traffic_from_ext_rtr(fip1)
        command2 = self.command_for_icmp_tcp_traffic_from_ext_rtr(fip2)
        self._remote_command_wo_server("noiro", "noir0123", ext_rtr, command1)
        self._remote_command_wo_server("noiro", "noir0123", ext_rtr, command2)

        print "Disassociate NSP from PTGs\n"
        self.update_gbp_policy_target_group(gbp, ptg1, "uuid", "", "", False, None)
        self.update_gbp_policy_target_group(gbp, ptg2, "uuid", "", "", False, None)

        print "Dynamically Associate FIPs to VMs\n"
        fip1 = self.admin_attach_floating_ip(vm1, ext_net_list[0].get("network"))
        fip2 = self.admin_attach_floating_ip(vm2, ext_net_list[0].get("network"))
        self.sleep_between(10, 15)

        command3 = self.command_for_icmp_tcp_traffic_from_ext_rtr(fip1['ip'])
        command4 = self.command_for_icmp_tcp_traffic_from_ext_rtr(fip2['ip'])

        print "\nDNATed Traffic from ExtRTR to VMs after NSP is removed from PTG\n ICMP and TCP test from external router"
        self._remote_command_wo_server("noiro", "noir0123", ext_rtr, command3)
        self._remote_command_wo_server("noiro", "noir0123", ext_rtr, command4)

        print "Disassociate FIPs from all VMs\n"
        self.cleanup_ns(gbp, [vm1, vm2], [fip1, fip2], ext_net_list)
