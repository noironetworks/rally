from rally import consts
from rally.common import validation
from noirotest_framework import create_resources
from rally.noirotest_framework import gbputils
from rally.noirotest_framework import osutils
from rally.plugins.openstack import scenario
from rally.plugins.openstack.scenarios.neutron import utils as neutron_utils
from rally.plugins.openstack.scenarios.nova import utils as nova_utils


@validation.add("required_services", services=[consts.Service.NOVA, consts.Service.NEUTRON])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(name="ScenarioPlugin.east_west_test_diff_ptg_same_l2p_l3p",
                    context={"cleanup@openstack": ["nova", "neutron"]}, platform="openstack")
class EastWest(neutron_utils.NeutronScenario, gbputils.GBPScenario, osutils.OSScenario, nova_utils.NovaScenario,
               scenario.OpenStackScenario, create_resources.CreateResources):

    def run(self, controller_ip, image, flavor):
        gbp_ad = self.gbp_client(controller_ip, "admin", "noir0123", "admin")
        gbp, key_name, user, project = self.create_gbp_object_for_new_user(controller_ip, 'EWTEST', 'ewtest', 'noir0123', 'ewtest')
        policy_rule_set = self.create_gbp_policy_rule_set_east_west(gbp)

        l3p = self.create_gbp_l3policy(gbp, "demo_diff_ptg_same_l2p_l3p",
                                       **{"ip_pool": "6.6.6.0/24", "subnet_prefix_length": "28"})
        l2p = self.create_gbp_l2policy(gbp, "demo_diff_ptg_same_l2p_l3p_bd", False, False, **{"l3_policy_id": l3p})
        ptg1 = self.create_gbp_policy_target_group(gbp, "demo_diff_ptg_same_l2p_l3p_ptg1", **{"l2_policy_id": l2p})
        ptg2 = self.create_gbp_policy_target_group(gbp, "demo_diff_ptg_same_l2p_l3p_ptg2", **{"l2_policy_id": l2p})

        pt1, port1 = self.create_gbp_policy_target(gbp, "vm4_data_pt", "demo_diff_ptg_same_l2p_l3p_ptg1", 1)
        pt2, port2 = self.create_gbp_policy_target(gbp, "vm5_data_pt", "demo_diff_ptg_same_l2p_l3p_ptg2", 1)
        pt3, port3 = self.create_gbp_policy_target(gbp, "vm6_data_pt", "demo_diff_ptg_same_l2p_l3p_ptg2", 1)

        vm4 = self.boot_server(port1, key_name, image, flavor)
        vm5 = self.boot_server(port2, key_name, image, flavor)
        vm6 = self.boot_server(port3, key_name, image, flavor)

        policy_target_groups = [ptg1, ptg2]
        vm_list = [vm4, vm5, vm6]

        print("Traffic verification for same_host")
        self.verify_traffic()
        self.verify_traffic_with_no_rule(gbp, policy_target_groups, policy_rule_set)
        self.verify_traffic_with_icmp(gbp, policy_target_groups, policy_rule_set)
        self.verify_traffic_with_tcp(gbp, policy_target_groups, policy_rule_set)
        self.verify_traffic_with_icmp_and_tcp(gbp, policy_target_groups, policy_rule_set)
        self.verify_traffic_with_icmp_and_udp(gbp, policy_target_groups, policy_rule_set)
        self.verify_traffic_with_all_rules(gbp, policy_target_groups, policy_rule_set)
        self.verify_traffic_with_rem_apply_udp_back(gbp, policy_rule_set)
        self.verify_traffic_with_rem_add_tcp(gbp, policy_rule_set)
        self.verify_traffic_with_rem_add_icmp_udp(gbp, policy_rule_set)
        self.verify_traffic_with_no_contact(gbp, policy_target_groups)

        print("Traffic verification for diff_host_diff_leaf")
        self.traffic_with_no_contact_for_diff_host_diff_leaf()
        self.traffic_with_no_rules_for_diff_host_diff_leaf(gbp, policy_target_groups, policy_rule_set)
        self.traffic_with_icmp_for_diff_host_diff_leaf(gbp, policy_target_groups, policy_rule_set)
        self.traffic_with_tcp_for_diff_host_diff_leaf(gbp, policy_target_groups, policy_rule_set)
        self.traffic_with_icmp_tcp_for_diff_host_diff_leaf(gbp, policy_target_groups, policy_rule_set)
        self.traffic_with_icmp_udp_for_diff_host_diff_leaf(gbp, policy_target_groups, policy_rule_set)
        self.traffic_with_all_icmp_tcp_udp_for_diff_host_diff_leaf(gbp, policy_target_groups, policy_rule_set)
        self.traffic_with_rem_add_udp_for_diff_host_diff_leaf(gbp, policy_rule_set)
        self.traffic_with_all_proto_for_diff_host_diff_leaf(gbp, policy_rule_set)
        self.traffic_with_rem_add_tcp_for_diff_host_diff_leaf(gbp, policy_rule_set)
        self.traffic_with_rem_add_icmp_udp_for_diff_host_diff_leaf(gbp, policy_rule_set)
        self.traffic_with_no_contacts_for_diff_host_diff_leaf(gbp, policy_target_groups)

        self.cleanup(vm_list, gbp_ad)

    def verify_traffic(self):
        print(
            "\nTest_1_Traff_With_No_PRS 10 Traffic Sub-Testcases with NO CONTRACT for arp,dns,dhcp,udp,icmp and their combos")
        ########################################################
        # traffic verification with no contract
        #######################################

    def verify_traffic_with_no_rule(self, gbp_obj, ptgs, policy_rule_set):
        print(
            "\nTest_2_Traff_Apply_PRS_No_Rule: 10 Traffic Sub-Testcases with CONTRACT But NO RULE for arp,dns,dhcp,tcp,udp,icmp and their combos")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["norule_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["norule_id"], "")
        ########################################################
        # traffic verification with prs_norule
        #######################################

    def verify_traffic_with_icmp(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_3_Traff_Apply_PRS_ICMP: Apply ICMP CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["icmp_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["icmp_id"], "")
        ########################################################
        # traffic verification with prs_icmp proto=icmp
        #######################################

    def verify_traffic_with_tcp(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_4_Traff_Apply_PRS_TCP: Apply TCP CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["tcp_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["tcp_id"], "")
        ########################################################
        # traffic verification with prs_tcp proto=tcp
        #######################################

    def verify_traffic_with_icmp_and_tcp(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_5_Traff_Apply_PRS_TCP: Apply TCP CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["icmp_tcp_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["icmp_tcp_id"], "")
        ########################################################
        # traffic verification with prs_tcp proto=tcp
        #######################################

    def verify_traffic_with_icmp_and_udp(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_6_Traff_Apply_PRS_TCP: Apply TCP CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["icmp_udp_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["icmp_udp_id"], "")
        ########################################################
        # traffic verification with prs_tcp proto=tcp
        #######################################

    def verify_traffic_with_all_rules(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_7_Traff_Apply_PRS_All_Proto: Apply ICMP-TCP-UDP combo CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["allrule_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["allrule_id"], "")
        ########################################################
        # traffic verification with prs_all proto=icmp,tcp,udp
        #######################################

    def verify_traffic_with_rem_apply_udp_back(self, gbp_obj, policy_rule_set):
        print("\nTest_8_Traff_Rem_Add_UDP_Rule: Remove and Apply back UDP Rule from CONTRACT and Verify Traffic")
        self.update_gbp_policy_rule_set(gbp_obj, "demo_ruleset_all", **{"policy_rules": [policy_rule_set["icmp_id"], policy_rule_set["tcp_id"]]})
        ########################################################
        # traffic verification with updated prs_all proto=icmp,tcp
        #######################################

        # if traffic out=1
    def verify_traffic_with_all_rules(self, gbp_obj, policy_rule_set):
        print("Adding TCP,UDP,ICMP PRs back to All-Proto PRS and Verify Traffic")
        self.update_gbp_policy_rule_set(gbp_obj, "demo_ruleset_all",
                                        **{"policy_rules": [policy_rule_set["icmp_id"], policy_rule_set["tcp_id"],
                                                            policy_rule_set["udp_id"]]})
        ########################################################
        # traffic verification with updated prs_all proto=icmp,tcp,udp
        #######################################

    def verify_traffic_with_rem_add_tcp(self, gbp_obj, policy_rule_set):
        print("\nTest_9_Traff_Rem_Add_TCP_Rule: Remove and Apply back TCP Rule from CONTRACT and Verify Traffic")
        self.update_gbp_policy_rule_set(gbp_obj, "demo_ruleset_all", **{"policy_rules": [policy_rule_set["icmp_id"],
                                                            policy_rule_set["udp_id"]]})
        ########################################################
        # traffic verification with updated prs_all proto=icmp,udp
        #######################################
        # if traffic out=1

    def verify_traffic_with_rem_add_icmp_udp(self, gbp_obj, policy_rule_set):
        print(
            "\nTest_9A_Traff_Rem_Add_ICMP_UDP_Rule: Remove and Apply back ICMP & UDP Rules from CONTRACT and Verify Traffic")
        self.update_gbp_policy_rule_set(gbp_obj, "demo_ruleset_all", **{"policy_rules": policy_rule_set["tcp_id"]})
        ########################################################
        # traffic verification with updated prs_all proto=tcp
        #######################################
        # if traffic out=1

    def traffic_with_all_rules(self,  gbp_obj, policy_rule_set):
        print("Adding TCP,UDP,ICMP PRs back to All-Proto PRS and Verify Traffic")
        self.update_gbp_policy_rule_set(gbp_obj, "demo_ruleset_all",
                                        **{"policy_rules": [policy_rule_set["icmp_id"], policy_rule_set["tcp_id"],
                                                            policy_rule_set["udp_id"]]})
        ########################################################
        # traffic verification with updated prs_all proto=icmp,tcp,udp
        #######################################

    def verify_traffic_with_no_contact(self,  gbp_obj, ptgs, policy_rule_set):
        print("\nTest_11_Traff_Rem_PRS: 10 Traffic Sub-Testcases REMOVE CONTRACT and verify traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", "")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", "", "")
        ########################################################
        # traffic verification with no contract
        #######################################

        print("Traffic verification for diff_host_diff_leaf")
    def traffic_with_no_contact_for_diff_host_diff_leaf(self):
        print(
            "\nTest_1_Traff_With_No_PRS 10 Traffic Sub-Testcases with NO CONTRACT for arp,dns,dhcp,udp,icmp and their combos")
        ########################################################
        # traffic verification with no contract
        #######################################

    def traffic_with_no_rules_for_diff_host_diff_leaf(self,  gbp_obj, ptgs, policy_rule_set):
        print(
            "\nTest_2_Traff_Apply_PRS_No_Rule: 10 Traffic Sub-Testcases with CONTRACT But NO RULE for arp,dns,dhcp,tcp,udp,icmp and their combos")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "",  policy_rule_set["norule_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["norule_id"], "")
        ########################################################
        # traffic verification with prs_norule
        #######################################

    def traffic_with_icmp_for_diff_host_diff_leaf(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_3_Traff_Apply_PRS_ICMP: Apply ICMP CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["icmp_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["icmp_id"], "")
        ########################################################
        # traffic verification with prs_icmp proto=icmp
        #######################################

    def traffic_with_tcp_for_diff_host_diff_leaf(self,  gbp_obj, ptgs, policy_rule_set):
        print("\nTest_4_Traff_Apply_PRS_TCP: Apply TCP CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["tcp_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["tcp_id"], "")
        ########################################################
        # traffic verification with prs_tcp proto=tcp
        #######################################

    def traffic_with_icmp_tcp_for_diff_host_diff_leaf(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_5_Traff_Apply_PRS_ICMP_TCP: Apply ICMP-TCP combo CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["icmp_tcp_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["icmp_tcp_id"], "")
        ########################################################
        # traffic verification with prs_icmp_tcp proto=icmp,tcp
        #######################################

    def traffic_with_icmp_udp_for_diff_host_diff_leaf(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_6_Traff_Apply_PRS_ICMP_UDP: Apply ICMP-UDP combo CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["icmp_udp_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["icmp_udp_id"], "")
        ########################################################
        # traffic verification with prs_icmp_udp proto=icmp,udp
        #######################################

    def traffic_with_all_icmp_tcp_udp_for_diff_host_diff_leaf(self,  gbp_obj, ptgs, policy_rule_set):
        print("\nTest_7_Traff_Apply_PRS_All_Proto: Apply ICMP-TCP-UDP combo CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["allrule_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["allrule_id"], "")
        ########################################################
        # traffic verification with prs_all proto=icmp,tcp,udp
        #######################################

    def traffic_with_rem_add_udp_for_diff_host_diff_leaf(self,  gbp_obj, policy_rule_set):
        print("\nTest_8_Traff_Rem_Add_UDP_Rule: Remove and Apply back UDP Rule from CONTRACT and Verify Traffic")
        self.update_gbp_policy_rule_set(gbp_obj, "demo_ruleset_all", **{"policy_rules": [policy_rule_set["icmp_id"], policy_rule_set["tcp_id"]]})
        ########################################################
        # traffic verification with updated prs_all proto=icmp,tcp
        #######################################

    def traffic_with_all_proto_for_diff_host_diff_leaf(self, gbp_obj, policy_rule_set):
        # if traffic out=1
        print("Adding TCP,UDP,ICMP PRs back to All-Proto PRS and Verify Traffic")
        self.update_gbp_policy_rule_set(gbp_obj, "demo_ruleset_all",
                                        **{"policy_rules": [policy_rule_set["icmp_id"], policy_rule_set["tcp_id"], policy_rule_set["udp_id"]]})
        ########################################################
        # traffic verification with updated prs_all proto=icmp,tcp,udp
        #######################################

    def traffic_with_rem_add_tcp_for_diff_host_diff_leaf(self, gbp_obj, policy_rule_set):
        print("\nTest_9_Traff_Rem_Add_TCP_Rule: Remove and Apply back TCP Rule from CONTRACT and Verify Traffic")
        self.update_gbp_policy_rule_set(gbp_obj, "demo_ruleset_all", **{"policy_rules": [policy_rule_set["icmp_id"], policy_rule_set["udp_id"]]})
        ########################################################
        # traffic verification with updated prs_all proto=icmp,udp
        #######################################
        # if traffic out=1
        print("Adding TCP,UDP,ICMP PRs back to All-Proto PRS and Verify Traffic")
        self.update_gbp_policy_rule_set(gbp_obj, "demo_ruleset_all",
                                        **{"policy_rules": [policy_rule_set["icmp_id"], policy_rule_set["tcp_id"], policy_rule_set["udp_id"]]})
        ########################################################
        # traffic verification with updated prs_all proto=icmp,tcp,udp
        #######################################

    def traffic_with_rem_add_icmp_udp_for_diff_host_diff_leaf(self, gbp_obj, policy_rule_set):
        print(
            "\nTest_9A_Traff_Rem_Add_ICMP_UDP_Rule: Remove and Apply back ICMP & UDP Rules from CONTRACT and Verify Traffic")
        self.update_gbp_policy_rule_set(gbp_obj, "demo_ruleset_all", **{"policy_rules": [policy_rule_set["tcp_id"]]})
        ########################################################
        # traffic verification with updated prs_all proto=tcp
        #######################################
        # if traffic out=1
        print("Adding TCP,UDP,ICMP PRs back to All-Proto PRS and Verify Traffic")
        self.update_gbp_policy_rule_set(gbp_obj, "demo_ruleset_all",
                                        **{"policy_rules": [policy_rule_set["icmp_id"], policy_rule_set["tcp_id"], policy_rule_set["udp_id"]]})
        ########################################################
        # traffic verification with updated prs_all proto=icmp,tcp,udp
        #######################################

    def traffic_with_no_contacts_for_diff_host_diff_leaf(self, gbp_obj, ptgs):
        print("\nTest_11_Traff_Rem_PRS: 10 Traffic Sub-Testcases REMOVE CONTRACT and verify traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", "")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", "", "")
        ########################################################
        # traffic verification with no contract
        #######################################



