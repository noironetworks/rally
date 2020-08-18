from rally import consts
from rally.common import validation
from rally.noirotest_framework import create_resources
from rally.noirotest_framework import gbputils
from rally.noirotest_framework import osutils
from rally.plugins.openstack import scenario
from rally.plugins.openstack.scenarios.neutron import utils as neutron_utils
from rally.plugins.openstack.scenarios.nova import utils as nova_utils


@validation.add("required_services", services=[consts.Service.NOVA, consts.Service.NEUTRON])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(name="ScenarioPlugin.east_west_test_same_ptg_same_l2p_same_l3p",
                    context={"cleanup@openstack": ["nova", "neutron"]}, platform="openstack")
class EastWest(neutron_utils.NeutronScenario, gbputils.GBPScenario, osutils.OSScenario, nova_utils.NovaScenario,
               scenario.OpenStackScenario, create_resources.CreateResources):

    def run(self, controller_ip, image, flavor):
        plugin_type = 'merged'
        gbp_ad = self.gbp_client(controller_ip, "admin", "noir0123", "admin")
        gbp, key_name, user, project = self.create_gbp_object_for_new_user(controller_ip, 'EWTEST',
                                                                           'ewtest', 'noir0123', 'ewtest')
        policy_rule_set = self.create_gbp_policy_rule_set_east_west(gbp)

        l3p = self.create_gbp_l3policy(gbp, "demo_same_ptg_l2p_l3p",
                                       **{"ip_pool": "5.5.5.0/24", "subnet_prefix_length": "28"})
        l2p = self.create_gbp_l2policy(gbp, "demo_same_ptg_l2p_l3p_bd", False, False, **{"l3_policy_id": l3p})
        ptg = self.create_gbp_policy_target_group(gbp, "demo_same_ptg_l2p_l3p_ptg", **{"l2_policy_id": l2p})

        pt1, port1 = self.create_gbp_policy_target(gbp, "vm1_data_pt", "demo_same_ptg_l2p_l3p_ptg", 1)
        pt2, port2 = self.create_gbp_policy_target(gbp, "vm2_data_pt", "demo_same_ptg_l2p_l3p_ptg", 1)
        pt3, port3 = self.create_gbp_policy_target(gbp, "vm3_data_pt", "demo_same_ptg_l2p_l3p_ptg", 1)

        vm1 = self.boot_server(port1, key_name, image, flavor)
        vm2 = self.boot_server(port2, key_name, image, flavor)
        vm3 = self.boot_server(port3, key_name, image, flavor)

        vm_list = [vm1, vm2, vm3]
        print("Starting traffic verification...")
        self.verify_traffic(gbp, ptg, plugin_type)
        self.verify_traffic_with_no_rules(gbp, ptg, policy_rule_set)
        self.verify_traffic_with_icmp(gbp, ptg, policy_rule_set)
        self.traffic_with_tcp(gbp, ptg, policy_rule_set)
        self.traffic_with_icmp(gbp, ptg, policy_rule_set)
        self.verify_traffic_with_icmp_tcp(gbp, ptg, policy_rule_set)
        self.verify_traffic_with_icmp_udp(gbp, ptg, policy_rule_set)
        self.verify_traffic_with_all_proto(gbp, ptg, policy_rule_set)
        self.verify_traffic_with_no_rules(gbp, ptg, policy_rule_set)
        self.verify_traffic_with_no_contact(gbp, ptg)
        self.verify_traffic_for_diff_host_diff_leaf(gbp, ptg, plugin_type)
        self.traffic_with_no_rules_for_diff_host_diff_leaf(gbp, ptg, policy_rule_set)
        self.traffic_with_icmp_for_diff_host_diff_leaf(gbp, ptg, policy_rule_set)
        self.traffic_with_tcp_for_diff_host_diff_leaf(gbp, ptg, policy_rule_set)
        self.traffic_with_icmp_tcp_for_diff_host_diff_leaf(gbp, ptg, policy_rule_set)
        self.traffic_with_icmp_udp_for_diff_host_diff_leaf(gbp, ptg, policy_rule_set)
        self.traffic_with_all_proto_for_diff_host_diff_leaf(gbp, ptg, policy_rule_set)
        self.traffic_with_no_contacts_for_diff_host_diff_leaf(gbp, ptg)

        self.cleanup(vm_list, gbp_ad)

    def verify_traffic(self, gbp1, ptg, plugin_type):
        print("Traffic verification for same_host")

        for flag in ['enforced', 'unenforced']:
            if flag == 'enforced':
                if plugin_type:
                    self.update_gbp_policy_target_group(gbp1, ptg, "uuid", **{"intra_ptg_allow": False})
                else:
                    #####################################################
                    # add enforced to ptg
                    #########################
                    pass
            else:
                if plugin_type:
                    self.update_gbp_policy_target_group(gbp1, ptg, "uuid", **{"intra_ptg_allow": True})
                else:
                    #####################################################
                    # add enforced to ptg
                    #########################
                    pass

            print(
                "\nTest_1_Traff_With_No_PRS: 10 Traffic Sub-Testcases with NO CONTRACT for arp,dns,dhcp,tcp,udp,icmp and their combos")
            ########################################################
            # traffic verification with no contract
            #######################################

    def verify_traffic_with_no_rules(self, gbp, ptg, prs_ids):
        print(
            "\nTest_2_Traff_Apply_PRS_No_Rule: 10 Traffic Sub-Testcases with CONTRACT But NO RULE for arp,dns,dhcp,tcp,udp,icmp and their combos")
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", prs_ids["norule_id"], prs_ids["norule_id"])
        ########################################################
        # traffic verification with prs_norule
        #######################################

    def verify_traffic_with_icmp(self, gbp, ptg, prs_ids):
        print("\nTest_3_Traff_Apply_PRS_ICMP: Apply ICMP CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", prs_ids["icmp_id"], prs_ids["icmp_id"])
        ########################################################
        # traffic verification with prs_icmp
        #######################################

    def verify_traffic_with_tcp(self, gbp, ptg, prs_ids):
        print("\nTest_4_Traff_Apply_PRS_TCP: Apply TCP CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", prs_ids["tcp_id"], prs_ids["tcp_id"])
        ########################################################
        # traffic verification with prs_tcp
        #######################################

    def verify_traffic_with_icmp_tcp(self, gbp, ptg, prs_ids):
        print("\nTest_5_Traff_Apply_PRS_ICMP_TCP: Apply ICMP-TCP combo CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", prs_ids["icmp_tcp_id"], prs_ids["icmp_tcp_id"])
        ########################################################
        # traffic verification with prs_icmp_tcp
        #######################################

    def verify_traffic_with_icmp_udp(self, gbp, ptg, prs_ids):
        print("\nTest_6_Traff_Apply_PRS_ICMP_UDP: Apply ICMP-UDP combo CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", ["icmp_udp_id"], prs_ids["icmp_udp_id"])
        ########################################################
        # traffic verification with prs_icmp_udp
        #######################################

    def verify_traffic_with_all_proto(self, gbp, ptg, prs_ids):
        print("\nTest_7_Traff_Apply_PRS_All_Proto: Apply ICMP-TCP-UDP combo CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", prs_ids["allrule_id"], prs_ids["allrule_id"])
        ########################################################
        # traffic verification with prs_all
        #######################################

    def verify_traffic_with_no_contact(self, gbp, ptg):
        print(
            "\nTest_8_Traff_Rem_PRS: 10 Traffic Sub-Testcases REMOVE CONTRACT for arp,dns,dhcp,tcp,udp,icmp and their combos")
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", "", "")
        ########################################################
        # traffic verification with no contract
        #######################################

    def verify_traffic_for_diff_host_diff_leaf(self, gbp, ptg, plugin_type):
        print("\nTraffic verification for diff_host_diff_leaf")

        for flag in ['enforced', 'unenforced']:
            if flag == 'enforced':
                if plugin_type:
                    self.update_gbp_policy_target_group(gbp, ptg, "uuid", **{"intra_ptg_allow": False})
                else:
                    #####################################################
                    # add enforced to ptg
                    ########w#################
                    pass
            else:
                if plugin_type:
                    self.update_gbp_policy_target_group(gbp, ptg, "uuid", **{"intra_ptg_allow": True})
                else:
                    #####################################################
                    # add enforced to ptg
                    #########################
                    pass

            print(
                "\nTest_1_Traff_With_No_PRS: 10 Traffic Sub-Testcases with NO CONTRACT for arp,dns,dhcp,tcp,udp,icmp and their combos")
            ########################################################
            # traffic verification with no contract
            #######################################

    def traffic_with_no_rules_for_diff_host_diff_leaf(self, gbp, ptg, prs_ids):
        print(
            "\nTest_2_Traff_Apply_PRS_No_Rule: 10 Traffic Sub-Testcases with CONTRACT But NO RULE for arp,dns,dhcp,tcp,udp,icmp and their combos")
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", prs_ids["norule_id"], prs_ids["norule_id"])
        ########################################################
        # traffic verification with prs_norule
        #######################################

    def traffic_with_icmp_for_diff_host_diff_leaf(self, gbp, ptg, prs_ids):
        print("\nTest_3_Traff_Apply_PRS_ICMP: Apply ICMP CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", prs_ids["icmp_id"], prs_ids["icmp_id"])
        ########################################################
        # traffic verification with prs_icmp
        #######################################

    def traffic_with_tcp_for_diff_host_diff_leaf(self, gbp, ptg, prs_ids):
        print("\nTest_4_Traff_Apply_PRS_TCP: Apply TCP CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", prs_ids["tcp_id"], prs_ids["tcp_id"])
        ########################################################
        # traffic verification with prs_tcp
        #######################################

    def traffic_with_icmp_tcp_for_diff_host_diff_leaf(self, gbp, ptg, prs_ids):
        print("\nTest_5_Traff_Apply_PRS_ICMP_TCP: Apply ICMP-TCP combo CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", prs_ids["icmp_tcp_id"], prs_ids["icmp_tcp_id"])
        ########################################################
        # traffic verification with prs_icmp_tcp
        #######################################

    def traffic_with_icmp_udp_for_diff_host_diff_leaf(self, gbp, ptg, prs_ids):
        print("\nTest_6_Traff_Apply_PRS_ICMP_UDP: Apply ICMP-UDP combo CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", prs_ids["icmp_udp_id"], prs_ids["icmp_udp_id"])
        ########################################################
        # traffic verification with prs_icmp_udp
        #######################################

    def traffic_with_all_proto_for_diff_host_diff_leaf(self, gbp, ptg, prs_ids):
        print("\nTest_7_Traff_Apply_PRS_All_Proto: Apply ICMP-TCP-UDP combo CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", prs_ids["allrule_id"], prs_ids["allrule_id"])
        ########################################################
        # traffic verification with prs_all
        #######################################

    def traffic_with_no_contacts_for_diff_host_diff_leaf(self, gbp, ptg):
        print(
             "\nTest_8_Traff_Rem_PRS: 10 Traffic Sub-Testcases REMOVE CONTRACT for arp,dns,dhcp,tcp,udp,icmp and their combos")
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", "", "")
        ########################################################
        # traffic verification with no contract
        #######################################

