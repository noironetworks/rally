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
@scenario.configure(name="ScenarioPlugin.north_south_test9", context={"cleanup@openstack": ["nova", "neutron"],
                    "keypair@openstack": {}, "allow_ssh@openstack": None}, platform="openstack")

class NorthSouth(create_resources.CreateResources, osutils.OSScenario, gbputils.GBPScenario, neutron_utils.NeutronScenario,
                nova_utils.NovaScenario, scenario.OpenStackScenario):

    def run(self, controller_ip, image, flavor, L3OUT1, L3OUT1_NET, L3OUT1_VRF, L3OUT2,
            L3OUT2_NET, L3OUT2_VRF, ext_rtr, extrtr_ip1, extrtr_ip2, gwip1_extrtr, nova_az, plugin_type):

        gbp = self.gbp_client(controller_ip, "admin", "noir0123", "admin")

        if plugin_type:
            ext_net_list, ext_sub_list = self.create_external_networks_subnets(L3OUT1, L3OUT1_NET, L3OUT2, L3OUT2_NET)

        policy_rule_set, policy_rules = self.create_gbp_policy_rule_set_north_south(gbp)

        print("Execution of Testcase north_south_test9 starts")
        print("Create External Segment "+L3OUT1)
        ext_seg = self.create_gbp_external_segment(gbp, L3OUT1,
                                                   **{"subnet_id": ext_sub_list[0].get("subnet")["id"],
                                                      "external_routes": [{"destination": "0.0.0.0/0", "nexthop": None}],
                                                      "shared": True})

        print("Create Policy Target group with Default L3P")
        ptg1 = self.create_gbp_policy_target_group(gbp, "TestPtg1")
        defaultl3p = self.verify_gbp_l3policy(gbp, "default")

        print("Create non-default L3Policy and L2Policy")
        l3p = self.create_gbp_l3policy(gbp, "L3PNat", **{"ip_pool": "20.20.20.0/24", "subnet_prefix_length": "26"})
        l2p = self.create_gbp_l2policy(gbp, "L2PNat", False, False, **{"l3_policy_id": l3p})

        print("Create Policy Target group with Created L3P")
        ptg2 = self.create_gbp_policy_target_group(gbp, "TestPtg2", **{"l2_policy_id": l2p})

        print("Create Policy Targets for each of the two PTGs")
        pt1, port1 = self.create_gbp_policy_target(gbp, "pt1", "TestPtg1", 1)
        pt2, port2 = self.create_gbp_policy_target(gbp, "pt2", "TestPtg2", 1)

        print("Launch VMs with each ptg")
        vm1 = self.admin_boot_server(port1, image, flavor, "TestVM1")
        vm2 = self.admin_boot_server(port2, image, flavor, "TestVM2",  **{"availability_zone": nova_az})

        print("Create ExtPolicy with ExtSegment and Apply PolicyRuleSets")
        ext_pol = self.create_gbp_external_policy(gbp, L3OUT1_NET, **{"external_segments": [ext_seg]})

        print("Updating Policy Target Group and External Policy by applying Policy RuleSets")
        self.update_gbp_policy_target_group(gbp, ptg1, "uuid", "", [policy_rule_set["icmp_tcp_id"]])
        self.update_gbp_policy_target_group(gbp, ptg2, "uuid", "", [policy_rule_set["icmp_tcp_id"]])
        self.update_gbp_external_policy(gbp, ext_pol, "uuid", [policy_rule_set["icmp_tcp_id"]])

        print("Associate External Segment to both L3Ps")
        self.update_gbp_l3policy(gbp, l3p, "uuid", **{"external_segments": ext_seg})
        self.update_gbp_l3policy(gbp, defaultl3p, "uuid", **{"external_segments": ext_seg})

        print("Verify the Configured Objects and their Attributes")
        self.verify_ns_gbp_object(gbp, defaultl3p, l3p, l2p, ext_seg, "20.20.20.0/24", ext_pol, "", ptg2, "snat")
        self.sleep_between(15, 20)

        self.add_route_in_extrtr(ext_rtr, "55.55.55.0/24", gwip1_extrtr, "update")

        print("SNATed Traffic from VMs to ExtRTR")
        fip1 = self.admin_attach_floating_ip(vm1, ext_net_list[0].get("network"))
        fip2 = self.admin_attach_floating_ip(vm2, ext_net_list[0].get("network"))
        self.sleep_between(10, 15)

        command1 = self.command_for_start_http_server()
        command2 = self.command_for_icmp_tcp_traffic(extrtr_ip1)
        command3 = self.command_for_icmp_tcp_traffic(extrtr_ip2)
        command4 = self.command_for_stop_http_server()

        print("Sending Traffic from VM1 in to external router")
        self._remote_command("root", "noir0123", fip1['ip'], command1, vm1)
        self._remote_command("root", "noir0123", fip1['ip'], command2, vm1)
        self._remote_command("root", "noir0123", fip1['ip'], command3, vm1)
        self._remote_command("root", "noir0123", fip1['ip'], command4, vm1)
        print("Sending Traffic from VM2 in to external router")
        self._remote_command("root", "noir0123", fip2['ip'], command1, vm2)
        self._remote_command("root", "noir0123", fip2['ip'], command2, vm2)
        self._remote_command("root", "noir0123", fip2['ip'], command3, vm2)
        self._remote_command("root", "noir0123", fip2['ip'], command4, vm2)

        self.cleanup_ns(gbp, [vm1, vm2], [fip1, fip2], ext_net_list)
