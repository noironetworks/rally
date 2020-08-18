from rally import consts
from rally.common import validation
from rally.noirotest_framework import create_resources
from rally.plugins.openstack import scenario
from rally.noirotest_framework import gbputils
from rally.noirotest_framework import osutils
from rally.plugins.openstack.scenarios.nova import utils as nova_utils
from rally.plugins.openstack.scenarios.neutron import utils as neutron_utils


@validation.add("required_services", services=[consts.Service.NOVA, consts.Service.NEUTRON])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(name="ScenarioPlugin.gbp_sanity", context={"cleanup@openstack": ["nova", "neutron"]},
                    platform="openstack")
class GBPSanity(neutron_utils.NeutronScenario, gbputils.GBPScenario, osutils.OSScenario, nova_utils.NovaScenario,
                scenario.OpenStackScenario, create_resources.CreateResources):

    def run(self, controller_ip, image, flavor):

        dual_stack = False
        gbp_admin = self.gbp_client(controller_ip, "admin", "noir0123", "admin")
        gbp1, key_name, user, project = self.create_gbp_object_for_new_user(controller_ip, 'MANDRAKE',
                                                                           'mandrake', 'noir0123', 'mandrake')

        l2p1, l2p1_impl3p, l2p1_autoptg, l2p1_nw = self.create_gbp_l2policy(gbp1, "L2P1", True, True)
        l2p2, l2p2_autoptg, l2p2_nw = self.create_gbp_l2policy(gbp1, "L2P2", False, True,
                                                               **{"l3_policy_id": l2p1_impl3p})
        reg_ptg = self.create_gbp_policy_target_group(gbp1, "REGPTG", **{"l2_policy_id": l2p1})

        pt1, port1 = self.create_gbp_policy_target(gbp1, "pt1", reg_ptg, 1, "uuid")
        pt2, port2 = self.create_gbp_policy_target(gbp1, "pt2", l2p1_autoptg, 1, "uuid")
        pt3, port3 = self.create_gbp_policy_target(gbp1, "pt3", l2p1_autoptg, 1, "uuid")
        pt4, port4 = self.create_gbp_policy_target(gbp1, "pt4", l2p2_autoptg, 1, "uuid")

        gbp_vm_nw_ip = [[0, 0, 0, 0], [0, 0]]
        gbp_vm_nw_ip[0] = [{"port": port1, "netns": "qdhcp" + str(l2p1_nw), "tag": "intra_bd"},
                           {"port": port2, "netns": "qdhcp" + str(l2p1_nw), "tag": "intra_epg"},
                           {"port": port3, "netns": "qdhcp" + str(l2p1_nw), "tag": "intra_epg"},
                           {"port": port4, "netns": "qdhcp" + str(l2p2_nw), "tag": "inter_bd"}, ]

        act = self.create_gbp_policy_action(gbp_admin, "ALLOW", **{"action_type": "allow", "shared": True})
        act_id = self.verify_gbp_policy_action(gbp_admin, "ALLOW")
        cls_icmp_id, rule_icmp_id = self.create_gbp_classifier_and_policy_rule(gbp_admin, act_id, "ICMP",
                                                                               "icmp", "bi", "PR-ICMP", shared=True)
        if dual_stack:
            cls_icmpv6_id, rule_icmpv6_id = self.create_gbp_classifier_and_policy_rule(gbp_admin, act_id, "ICMPV6",
                                                       "58", "bi", "PR-ICMPV6", shared=True)

        cls_tcp_id, rule_tcp_id = self.create_gbp_classifier_and_policy_rule(gbp_admin, act_id, "TCP", "tcp", "bi",
                                                                             "PR-TCP", port_rang="20:2000", shared=True)

        if dual_stack:
            prs_icmp_tcp_id = self.create_gbp_policy_ruleset(gbp_admin, "CONT-ICMP-TCP",
                                                             rule_ids=[rule_icmp_id, rule_icmpv6_id, rule_tcp_id],
                                                             shared=True)
            prs_icmp_id = self.create_gbp_policy_ruleset(gbp_admin, "CONT-ICMP",
                                                         rule_ids=[rule_icmp_id, rule_icmpv6_id], shared=True)

        else:
            prs_icmp_tcp_id = self.create_gbp_policy_ruleset(gbp_admin, "CONT-ICMP-TCP",
                                                             rule_ids=[rule_icmp_id, rule_tcp_id],
                                                             shared=True)
            prs_icmp_id = self.create_gbp_policy_ruleset(gbp_admin, "CONT-ICMP",
                                                         rule_ids=[rule_icmp_id], shared=True)

        prs_tcp_id = self.create_gbp_policy_ruleset(gbp_admin, "CONT-ICMP-TCP", rule_ids=[rule_tcp_id], shared=True)

        prs_list = {"CONT-ICMP-TCP": prs_icmp_tcp_id, "CONT-ICMP": prs_icmp_id, "CONT-TCP": prs_tcp_id}

        vm1 = self.boot_server(port1, key_name, image, flavor)
        vm2 = self.boot_server(port2, key_name, image, flavor)
        vm3 = self.boot_server(port3, key_name, image, flavor)
        vm4 = self.boot_server(port4, key_name, image, flavor)

        self.verify_traffic_with_intra_egp(gbp1, reg_ptg, l2p1_autoptg, prs_icmp_tcp_id)
        self.verify_traffic_with_gbp_intra_bed(gbp1, reg_ptg, l2p2_autoptg, l2p1_autoptg, prs_icmp_tcp_id)

        ###################################################################
        # traffic verification gbp inter_bd
        #########################################################

        ext_net1 = self._admin_create_network('L3OUT1', {"shared": True, "router": True,
                                                         "apic:distinguished_names": {"type": "dict",
                                                                                      "ExternalNetwork": "uni/tn-common/out-Management-Out/instP-data_ext_pol"}})
        ext_sub1 = self._admin_create_subnet(ext_net1, {"cidr": '50.50.50.0/28', "no_dhcp": True}, None)
        ext_sub2 = self._admin_create_subnet(ext_net1,
                                             {"cidr": '55.55.55.0/28', "no_dhcp": True, "apic:snat_host_pool": True},
                                             None)

        ext_seg1 = self.create_gbp_external_segment(gbp_admin, "L3OUT1",
                                                    **{"subnet_id": ext_sub1.id, "external_routes": [
                                                        {"destination": "0.0.0.0/0", "nexthop": None}], "shared": True})
        ext_pol1 = self.create_gbp_external_policy(gbp1, "L3OUT1_NET", **{"external_segments": [ext_seg1]})
        self.update_gbp_l3policy(gbp1, l2p1_impl3p, "uuid", **{"external_segments": ext_seg1})

        self.update_gbp_external_policy(gbp1, ext_pol1, "uuid", [prs_icmp_tcp_id])
        self.update_gbp_policy_target_group(gbp1, reg_ptg, "uuid", None, [prs_icmp_tcp_id])
        self.update_gbp_policy_target_group(gbp1, l2p1_autoptg, "uuid", None, [prs_icmp_tcp_id])
        self.update_gbp_policy_target_group(gbp1, l2p2_autoptg, "uuid", None, [prs_icmp_tcp_id])
        self.sleep_between(5, 10)

        ########################################################################
        # traffic verification gbp intra_epg external
        #############################################################

        fip1 = self._attach_floating_ip(vm1, ext_net1)
        fip2 = self._attach_floating_ip(vm2, ext_net1)
        fip3 = self._attach_floating_ip(vm3, ext_net1)
        fip4 = self._attach_floating_ip(vm4, ext_net1)

        #################################################################
        # traffic verification gbp from external-router to fip
        ########################################################

        print("Creating project BATMAN and creating resources in it")
        gbp2, key_name2, user2, project2 = self.create_gbp_object_for_new_user(controller_ip, 'BATMAN',
                                                                            'batman', 'noir0123', 'batman')

        asc1 = self.create_address_scope("nonat_ads", "4", True, **{
            "apic:distinguished_names": {"type": "dict", "VRF": "uni/tn-common/ctx-L3OUT2_VRF"}})
        subpool1 = self.create_subnet_pool("nonat_sps", asc1.id, "60.60.60.0/24", "28", True)
        l3p = self.create_gbp_l3policy(gbp2, "L3P1", **{"subnetpools_v4": [subpool1.id]})
        l2p3, l2p3_autoptg, l2p3_nw = self.create_gbp_l2policy(gbp2, "L2P3", False, True, **{"l3_policy_id": l3p})

        pt5, port5 = self.create_gbp_policy_target(gbp2, "pt5", l2p3_autoptg, 1, "uuid")
        pt6, port6 = self.create_gbp_policy_target(gbp2, "pt6", l2p3_autoptg, 1, "uuid")
        gbp_vm_nw_ip[1] = [{"port": port5, "netns": "qdhcp" + str(l2p3_nw), "tag": "intra_epg"},
                           {"port": port6, "netns": "qdhcp" + str(l2p3_nw), "tag": "intra_epg"}]

        vm5 = self.boot_server(port5, key_name2, image, flavor)
        vm6 = self.boot_server(port6, key_name2, image, flavor)

        ext_net2 = self._admin_create_network('L3OUT2', {"shared": True, "router": True,
                                                         "apic:distinguished_names": {"type": "dict",
                                                                                      "ExternalNetwork": "uni/tn-common/out-Datacenter-Out/instP-data_ext_pol"},
                                                         "apic:nat_type": ""})
        ext_sub3 = self._admin_create_subnet(ext_net2, {"cidr": "2.3.4.0/24", "no_dhcp": True}, None)

        ext_seg2 = self.create_gbp_external_segment(gbp_admin, "L3OUT2",
                                                    **{"subnet_id": ext_sub3.id, "external_routes": [
                                                        {"destination": "0.0.0.0/0", "nexthop": None}], "shared": True})
        ext_pol2 = self.create_gbp_external_policy(gbp2, "L3OUT2_NET", **{"external_segments": [ext_seg2]})
        self.update_gbp_l3policy(gbp2, l3p, "uuid", **{"external_segments": ext_seg2})
        self.update_gbp_external_policy(gbp2, ext_pol2, "uuid", [prs_icmp_tcp_id])
        self.update_gbp_policy_target_group(gbp2, l2p3_autoptg, "uuid", None, [prs_icmp_tcp_id])

        #####################################################################
        # traffic verification gbp intra_epg
        ######################################################

        ######################################################cleanup
        for item in [vm5, vm6]:
            self._delete_server(item)
        self._delete_subnet_pool(subpool1.id)
        self._delete_address_scope(asc1.id)
        self._change_client(1, self.context, None, None)
        for i in range(1, 5):
            self._delete_server_with_fip(vm + str(i), fip + str(i))
        self.cleanup_gbp(gbp_admin)
        self._admin_delete_network(ext_net1)
        self._admin_delete_network(ext_net2)
        for item in [user, user2]:
            self._delete_user(item)
        for item in [project, project2]:
            self._delete_project(item)

    def verify_traffic_with_intra_egp(self, gbp, port_group1, port_group2, rule_set_id):
        ####################################################################
        # traffic verification gbp intra_epg
        ############################################################

        self.update_gbp_policy_target_group(gbp, port_group1, "uuid", "", [rule_set_id])
        self.update_gbp_policy_target_group(gbp, port_group2, "uuid", [rule_set_id])
        self.sleep_between(10, 15)

    def verify_traffic_with_gbp_intra_bed(self, gbp, port_group1, port_group2, port_group3, rule_set_id):
        #########################################################################
        # traffic verification gbp intra_bd
        ##########################################################

        self.update_gbp_policy_target_group(gbp, port_group2, "uuid", "", [rule_set_id])
        self.update_gbp_policy_target_group(gbp, port_group1, "uuid", [rule_set_id])
        self.update_gbp_policy_target_group(gbp, port_group3, "uuid", [rule_set_id])
