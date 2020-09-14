from rally.plugins.openstack import scenario
from rally.noirotest_framework import gbputils
from rally.noirotest_framework.osutils import TestError

class CreateResources(gbputils.GBPScenario, scenario.OpenStackScenario):

    def create_gbp_policy_rule_set_east_west(self, gbp1):

        policy_ruleset_ids = {}
        print("Create GBP policy action")
        self.create_gbp_policy_action(gbp1, "demo_act", **{"action_type": "allow", "shared": False})
        act_id = self.verify_gbp_policy_action(gbp1, "demo_act")
        print("Create GBP classifier and rule sets for ICMP")
        cls_icmp_id, rule_icmp_id = self.create_gbp_classifier_and_policy_rule(
            gbp1, act_id, "demo_class_icmp", "icmp", "bi", "demo_rule_icmp")
        prs_icmp_id = self.create_gbp_policy_ruleset(gbp1, "demo_ruleset_icmp", rule_ids=[rule_icmp_id])
        policy_ruleset_ids.update({"icmp_id": prs_icmp_id})

        print("Create GBP classifier and rule sets for TCP")
        cls_tcp_id, rule_tcp_id = self.create_gbp_classifier_and_policy_rule(
            gbp1, act_id, "demo_class_tcp", "tcp", "bi", "demo_rule_tcp")
        prs_tcp_id = self.create_gbp_policy_ruleset(gbp1, "demo_ruleset_tcp", [rule_tcp_id])
        policy_ruleset_ids.update({"tcp_id": prs_tcp_id})

        print("Create GBP classifier and rule sets for UDP")
        cls_udp_id, rule_udp_id = self.create_gbp_classifier_and_policy_rule(
            gbp1, act_id, "demo_class_icmp", "udp", "bi", "demo_rule_udp")
        prs_udp_id = self.create_gbp_policy_ruleset(gbp1, "demo_ruleset_udp", rule_ids=[rule_udp_id])
        policy_ruleset_ids.update({"udp_id": prs_udp_id})

        print("Create policy ruleset of ICMP and TCP")
        prs_icmp_tcp_id = self.create_gbp_policy_ruleset(gbp1, "demo_ruleset_icmp_tcp", rule_ids=[rule_icmp_id, rule_tcp_id])
        policy_ruleset_ids.update({"icmp_tcp_id": prs_icmp_tcp_id})

        print("Create policy ruleset of ICMP and UDP")
        prs_icmp_udp_id = self.create_gbp_policy_ruleset(gbp1, "demo_ruleset_icmp_udp", rule_ids=[rule_icmp_id, rule_udp_id])
        policy_ruleset_ids.update({"icmp_udp_id": prs_icmp_udp_id})

        print("Create policy ruleset of TCP and UDP")
        prs_tcp_udp_id = self.create_gbp_policy_ruleset(gbp1, "demo_ruleset_tcp_udp", rule_ids=[rule_tcp_id, rule_udp_id])
        policy_ruleset_ids.update({"tcp_udp_id": prs_tcp_udp_id})

        print("Create policy ruleset for all protocol")
        prs_all_id = self.create_gbp_policy_ruleset(gbp1, "demo_ruleset_all", rule_ids=[rule_icmp_id, rule_tcp_id, rule_udp_id])
        policy_ruleset_ids.update({"allrule_id": prs_all_id})

        print("Create policy ruleset for no rule ")
        prs_norule_id = self.create_gbp_policy_ruleset(gbp1, "demo_ruleset_norule")
        policy_ruleset_ids.update({"norule_id": prs_norule_id})

        return policy_ruleset_ids

    def create_gbp_classifier_and_policy_rule(self, gbp_obj, act_id, classifier_name,
                                              protocol, direction, policy_rule_name,
                                              port_rang=None, shared=False):

        if port_rang:
            self.create_gbp_policy_classifier(gbp_obj, classifier_name,
                                              **{"direction": direction, "protocol": protocol, "port_range": port_rang,
                                                 "shared": shared})
        else:
            self.create_gbp_policy_classifier(gbp_obj, classifier_name,
                                                     **{"direction": direction, "protocol": protocol, "shared": shared})
        cls_id = self.verify_gbp_policy_classifier(gbp_obj, classifier_name)
        self.create_gbp_policy_rule(gbp_obj, policy_rule_name, cls_id, act_id, "uuid",
                                                **{"shared": shared})
        rule_id = self.verify_gbp_policy_rule(gbp_obj, policy_rule_name)

        return cls_id, rule_id

    def create_gbp_policy_ruleset(self, gbp, policy_rule_set_name, rule_ids=[], shared=False):

        self.create_gbp_policy_rule_set(gbp, policy_rule_set_name, rule_ids, "uuid", **{"shared": shared})
        prs_id = self.verify_gbp_policy_rule_set(gbp, policy_rule_set_name)

        return prs_id

    def create_resources_for_north_south_tests(self, gbp_ad, gbp, key_name, image, flavor, external_seg2=False):
        ext_net1, ext_net2, ext_sub1, ext_sub2, ext_sub3 = self.create_external_netwok_subnet()
        ext_net_list = [ext_net1, ext_net2]
        ext_sub_list = [ext_sub1, ext_sub2, ext_sub3]
        ext_seg = self.create_gbp_external_segment(gbp_adm, "L3OUT1", **{"subnet_id": ext_sub1.id, "external_routes": [
            {"destination": "0.0.0.0/0", "nexthop": None}], "shared": True})

        print("Cretaing portgroups and gbp L3 and L2 Policy")
        ptg1 = self.create_gbp_policy_target_group(gbp, "TestPtg1")
        defaultl3p = self.verify_gbp_l3policy(gbp, "default")
        l3p = self.create_gbp_l3policy(gbp, "L3PNat", **{"ip_pool": "20.20.20.0/24", "subnet_prefix_length": "26"})
        l2p = self.create_gbp_l2policy(gbp, "L2PNat", False, False, **{"l3_policy_id": l3p})
        ptg2 = self.create_gbp_policy_target_group(gbp, "TestPtg2", **{"l2_policy_id": l2p})
        self.update_gbp_l3policy(gbp, l3p, "uuid", **{"external_segments": ext_seg})
        self.update_gbp_l3policy(gbp, defaultl3p, "uuid", **{"external_segments": ext_seg})

        pt1, port1 = self.create_gbp_policy_target(gbp, "pt1", "TestPtg1", 1)
        pt2, port2 = self.create_gbp_policy_target(gbp, "pt2", "TestPtg2", 1)
        vm1 = self.boot_server(port1, key_name, image, flavor)
        vm2 = self.boot_server(port2, key_name, image, flavor)
        vm_list = [vm1, vm2]

        ext_pol = self.create_gbp_external_policy(gbp, "L3OUT1_NET", **{"external_segments": [ext_seg]})
        self.create_gbp_policy_action(gbp_ad, "ALLOW", **{"action_type": "allow", "shared": True})
        act_id = self.verify_gbp_policy_action(gbp_ad, "ALLOW")
        cls_icmp_id, rule_icmp_id = self.create_gbp_classifier_and_policy_rule(gbp_ad, act_id, "ICMP",
                                                                               "icmp", "bi", "PR-ICMP", shared=True)
        cls_tcp_id, rule_tcp_id = self.create_gbp_classifier_and_policy_rule(gbp_ad, act_id, "TCP", "tcp", "bi",
                                                                             "PR-TCP", port_rang="20:2000", shared=True)
        prs_icmp_tcp_id = self.create_gbp_policy_ruleset(gbp_ad, rule_ids=[rule_icmp_id, rule_tcp_id], shared=True)
        self.update_gbp_external_policy(gbp, ext_pol, "uuid", [prs_icmp_tcp_id])
        self.update_gbp_policy_target_group(gbp, ptg1, "uuid", "", [prs_icmp_tcp_id])
        self.update_gbp_policy_target_group(gbp, ptg2, "uuid", "", [prs_icmp_tcp_id])

        nat_pool = self.create_gbp_nat_pool(gbp, "NatPoolTest1",
                                            **{"ip_pool": "50.50.50.0/24", "external_segment_id": ext_seg})
        try:
            self.verify_gbp_any_object(gbp, "l3_policy", l3p,
                                       **{"external_segments": ext_seg, "l2_policies": l2p, "ip_pool": "20.20.20.0/24"})
            self.verify_gbp_any_object(gbp, "l2_policy", l2p, **{"l3_policy_id": l3p, "policy_target_groups": ptg2})
            self.verify_gbp_any_object(gbp, "external_segment", ext_seg,
                                       **{"l3_policies": [defaultl3p, l3p], "nat_pools": nat_pool,
                                          "external_policies": ext_pol})
        except:
            raise TestError()

        if external_seg2:
            return ext_net_list, ext_sub_list, vm_list, l3p, defaultl3p, nat_pool, prs_icmp_tcp_id

        return ext_net_list, ext_sub_list, vm_list

    def cleanup(self, vm_list, gbp):
        for vm in vm_list:
            self._delete_server(vm)
        self.cleanup_gbp(gbp)

    def cleanup_resources(self, gbp_ad, vm_list, ext_net_list, fip2, fip1, user, project):
        self._delete_server_with_fip(vm_list[0], fip2)
        self._delete_server_with_fip(vm_list[1], fip1)
        self.cleanup_gbp(gbp_ad)
        self._admin_delete_network(ext_net_list[0])
        self._admin_delete_network(ext_net_list[1])
        self._delete_user(user)
        self._delete_project(project)