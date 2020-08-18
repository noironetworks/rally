from rally import consts
from rally.common import validation
from rally.noirotest_framework import gbputils
from rally.noirotest_framework import osutils
from rally.noirotest_framework import create_resources
from rally.plugins.openstack import scenario
from rally.plugins.openstack.scenarios.neutron import utils as neutron_utils
from rally.plugins.openstack.scenarios.nova import utils as nova_utils


@validation.add("required_services", services=[consts.Service.NOVA, consts.Service.NEUTRON])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(name="ScenarioPlugin.east_west_test_diff_ptg_diff_l2p_diff_l3p",
                    context={"cleanup@openstack": ["nova", "neutron"]}, platform="openstack")
class EastWest(neutron_utils.NeutronScenario, gbputils.GBPScenario, osutils.OSScenario, nova_utils.NovaScenario,
               scenario.OpenStackScenario, create_resources.CreateResources):

    def run(self, controller_ip, image, flavor):
        gbp_ad = self.gbp_client(controller_ip, "admin", "noir0123", "admin")
        gbp, key_name, user, project = self.create_gbp_object_for_new_user(controller_ip, 'EWTEST',
                                                                           'ewtest', 'noir0123', 'ewtest')
        policy_rule_set = self.create_gbp_policy_rule_set_east_west(gbp)

        l3p1 = self.create_gbp_l3policy(gbp, "demo_subnet_1",
                                        **{"ip_pool": "30.30.30.0/24", "subnet_prefix_length": "28"})
        l3p2 = self.create_gbp_l3policy(gbp, "demo_subnet_2",
                                        **{"ip_pool": "40.40.40.0/24", "subnet_prefix_length": "28"})
        l2p1 = self.create_gbp_l2policy(gbp, "demo_srvr_bd", False, False, **{"l3_policy_id": l3p1})
        l2p2 = self.create_gbp_l2policy(gbp, "demo_clnt_bd", False, False, **{"l3_policy_id": l3p2})
        ptg1 = self.create_gbp_policy_target_group(gbp, "demo_diff_ptg_l2p_l3p_ptg1", **{"l2_policy_id": l2p1})
        ptg2 = self.create_gbp_policy_target_group(gbp, "demo_diff_ptg_l2p_l3p_ptg2", **{"l2_policy_id": l2p2})

        pt1, port1 = self.create_gbp_policy_target(gbp, "vm10_data_pt", "demo_diff_ptg_l2p_l3p_ptg1", 1)
        pt2, port2 = self.create_gbp_policy_target(gbp, "vm11_data_pt", "demo_diff_ptg_l2p_l3p_ptg2", 1)
        pt3, port3 = self.create_gbp_policy_target(gbp, "vm12_data_pt", "demo_diff_ptg_l2p_l3p_ptg2", 1)

        vm10 = self.boot_server(port1, key_name, image, flavor)
        vm11 = self.boot_server(port2, key_name, image, flavor)
        vm12 = self.boot_server(port3, key_name, image, flavor)

        policy_target_groups = [ptg1, ptg2]
        vm_list = [vm10, vm11, vm12]

        self.traffic_verifaction()
        self.verify_traffic_with_norules(gbp, policy_target_groups, policy_rule_set)
        self.verify_traffic_with_icmp(gbp, policy_target_groups, policy_rule_set)
        self.verify_traffic_with_tcp(gbp, policy_target_groups, policy_rule_set)
        self.verify_traffic_with_udp(gbp, policy_target_groups, policy_rule_set)
        self.verify_traffic_with_icmp_tcp(gbp, policy_target_groups, policy_rule_set)
        self.verify_traffic_with_icmp_udp(gbp, policy_target_groups, policy_rule_set)
        self.verify_traffic_with_tcp_udp(gbp, policy_target_groups, policy_rule_set)
        self.verify_traffic_with_all_proto(gbp, policy_target_groups, policy_rule_set)
        self.verify_traffic_with_no_contact(gbp,policy_target_groups)
        self.traffic_with_no_contacts_for_diff_host_diff_leaf()
        self.traffic_with_no_rules_for_diff_host_diff_leaf(gbp, policy_target_groups, policy_rule_set)
        self.traffic_with_icmp_for_diff_host_diff_leaf(gbp, policy_target_groups, policy_rule_set)
        self.traffic_with_tcp_for_diff_host_diff_leaf(gbp, policy_target_groups, policy_rule_set)
        self.traffic_with_udp_for_diff_host_diff_leaf(gbp, policy_target_groups, policy_rule_set)
        self.traffic_with_icmp_tcp_for_diff_host_diff_leaf(gbp, policy_target_groups, policy_rule_set)
        self.traffic_with_icmp_udp_for_diff_host_diff_leaf(gbp, policy_target_groups, policy_rule_set)
        self.traffic_with_tcp_udp_for_diff_host_diff_leaf(gbp, policy_target_groups, policy_rule_set)
        self.traffic_with_all_proto_for_diff_host_diff_leaf(gbp, policy_target_groups, policy_rule_set)
        self.traffic_with_rem_contacts_for_diff_host_diff_leaf(gbp, policy_target_groups)
        self.cleanup(vm_list, gbp_ad)

    def traffic_verifaction(self):
        print("Traffic verification for same_host")

        print("\nTest_1_Traff_With_No_PRS: Run traff test when PTG is with NO Contract")
        ########################################################
        # traffic verification with no contract
        #######################################

    def verify_traffic_with_norules(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_2_Traff_Apply_PRS_No_Rule: Update the in-use PTG with a PRS which has NO-Rule")
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

    def verify_traffic_with_udp(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_5_Traff_Apply_PRS_UDP: Apply UDP CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["udp_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["udp_id"], "")
        ########################################################
        # traffic verification with prs_tcp proto=udp
        #######################################

    def verify_traffic_with_icmp_tcp(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_6_Traff_Apply_PRS_ICMP_TCP: Apply ICMP-TCP combo CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["icmp_tcp_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["icmp_tcp_id"], "")
        ########################################################
        # traffic verification with prs_icmp_tcp proto=icmp,tcp
        #######################################

    def verify_traffic_with_icmp_udp(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_7_Traff_Apply_PRS_ICMP_UDP: Apply ICMP-UDP combo CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["icmp_udp_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["icmp_udp_id"], "")
        ########################################################
        # traffic verification with prs_icmp_udp proto=icmp,udp
        #######################################

    def verify_traffic_with_tcp_udp(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_8_Traff_Apply_PRS_TCP_UDP: Apply TCP-UDP combo CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["tcp_udp_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["tcp_udp_id"], "")
        ########################################################
        # traffic verification with prs_icmp_udp proto=tcp,udp
        #######################################

    def verify_traffic_with_all_proto(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_9_Traff_Apply_PRS_All_Proto: Apply ICMP-TCP-UDP combo CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["allrule_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["allrule_id"], "")
        ########################################################
        # traffic verification with prs_all proto=icmp,tcp,udp
        #######################################

    def verify_traffic_with_no_contact(self, gbp_obj, ptgs):
        print("\nTest_10_Traff_With_Rem_PRS: Remove the PRS/Contract from the PTG and Test all traffic types")
        self.update_gbp_policy_target_group(gbp_obj, ptgs, "uuid", "", "")
        self.update_gbp_policy_target_group(gbp_obj, ptgs, "uuid", "", "")
        ########################################################
        # traffic verification with no contract
        #######################################

    def traffic_with_no_contacts_for_diff_host_diff_leaf(self):
        print("Traffic verification for diff_host_diff_leaf")

        print("\nTest_1_Traff_With_No_PRS: Run traff test when PTG is with NO Contract")
        ########################################################
        # traffic verification with no contract
        #######################################

    def traffic_with_no_rules_for_diff_host_diff_leaf(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_2_Traff_Apply_PRS_No_Rule: Update the in-use PTG with a PRS which has NO-Rule")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["norule_id"])
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

    def traffic_with_tcp_for_diff_host_diff_leaf(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_4_Traff_Apply_PRS_TCP: Apply TCP CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["tcp_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["tcp_id"], "")
        ########################################################
        # traffic verification with prs_tcp proto=tcp
        #######################################

    def traffic_with_udp_for_diff_host_diff_leaf(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_5_Traff_Apply_PRS_UDP: Apply UDP CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["udp_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["udp_id"], "")
        ########################################################
        # traffic verification with prs_tcp proto=udp
        #######################################

    def traffic_with_icmp_tcp_for_diff_host_diff_leaf(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_6_Traff_Apply_PRS_ICMP_TCP: Apply ICMP-TCP combo CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["icmp_tcp_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["icmp_tcp_id"], "")
        ########################################################
        # traffic verification with prs_icmp_tcp proto=icmp,tcp
        #######################################

    def traffic_with_icmp_udp_for_diff_host_diff_leaf(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_7_Traff_Apply_PRS_ICMP_UDP: Apply ICMP-UDP combo CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["icmp_udp_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["icmp_udp_id"], "")
        ########################################################
        # traffic verification with prs_icmp_udp proto=icmp,udp
        #######################################

    def traffic_with_tcp_udp_for_diff_host_diff_leaf(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_8_Traff_Apply_PRS_TCP_UDP: Apply TCP-UDP combo CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["tcp_udp_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["tcp_udp_id"], "")
        ########################################################
        # traffic verification with prs_icmp_udp proto=tcp,udp
        #######################################

    def traffic_with_all_proto_for_diff_host_diff_leaf(self, gbp_obj, ptgs, policy_rule_set):
        print("\nTest_9_Traff_Apply_PRS_All_Proto: Apply ICMP-TCP-UDP combo CONTRACT and Verify Traffic")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", policy_rule_set["allrule_id"])
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", policy_rule_set["allrule_id"], "")
        ########################################################
        # traffic verification with prs_all proto=icmp,tcp,udp
        #######################################

    def traffic_with_rem_contacts_for_diff_host_diff_leaf(self, gbp_obj, ptgs):
        print("\nTest_10_Traff_With_Rem_PRS: Remove the PRS/Contract from the PTG and Test all traffic types")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[0], "uuid", "", "")
        self.update_gbp_policy_target_group(gbp_obj, ptgs[1], "uuid", "", "")
        ########################################################
        # traffic verification with no contract
        #######################################

