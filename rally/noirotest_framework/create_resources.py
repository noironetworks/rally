from rally.plugins.openstack import scenario
from rally.noirotest_framework import gbputils
from rally.noirotest_framework.osutils import TestError

class CreateResources(gbputils.GBPScenario, scenario.OpenStackScenario):

    def create_gbp_policy_rule_set_east_west(self, gbp):

        policy_ruleset_ids = {}
        policy_rules = {}
        print("Create GBP policy action")
        self.create_gbp_policy_action(gbp, "demo_act", **{"action_type": "allow", "shared": False})
        act_id = self.verify_gbp_policy_action(gbp, "demo_act")
        print("Create GBP classifier and rule sets for ICMP")
        cls_icmp_id, rule_icmp_id = self.create_gbp_classifier_and_policy_rule(
            gbp, act_id, "demo_class_icmp", "icmp", "bi", "demo_rule_icmp")
        prs_icmp_id = self.create_gbp_policy_ruleset(gbp, "demo_ruleset_icmp", rule_ids=[rule_icmp_id])
        policy_ruleset_ids.update({"icmp_id": prs_icmp_id})
        policy_rules.update({"icmp_id": rule_icmp_id})

        print("Create GBP classifier and rule sets for TCP")
        cls_tcp_id, rule_tcp_id = self.create_gbp_classifier_and_policy_rule(
            gbp, act_id, "demo_class_tcp", "tcp", "bi", "demo_rule_tcp")
        prs_tcp_id = self.create_gbp_policy_ruleset(gbp, "demo_ruleset_tcp", [rule_tcp_id])
        policy_ruleset_ids.update({"tcp_id": prs_tcp_id})
        policy_rules.update({"tcp_id": rule_tcp_id})

        print("Create GBP classifier and rule sets for UDP")
        cls_udp_id, rule_udp_id = self.create_gbp_classifier_and_policy_rule(
            gbp, act_id, "demo_class_udp", "udp", "bi", "demo_rule_udp")
        prs_udp_id = self.create_gbp_policy_ruleset(gbp, "demo_ruleset_udp", rule_ids=[rule_udp_id])
        policy_ruleset_ids.update({"udp_id": prs_udp_id})
        policy_rules.update({"udp_id": rule_udp_id})

        print("Create policy ruleset of ICMP and TCP")
        prs_icmp_tcp_id = self.create_gbp_policy_ruleset(gbp, "demo_ruleset_icmp_tcp", rule_ids=[rule_icmp_id, rule_tcp_id])
        policy_ruleset_ids.update({"icmp_tcp_id": prs_icmp_tcp_id})

        print("Create policy ruleset of ICMP and UDP")
        prs_icmp_udp_id = self.create_gbp_policy_ruleset(gbp, "demo_ruleset_icmp_udp", rule_ids=[rule_icmp_id, rule_udp_id])
        policy_ruleset_ids.update({"icmp_udp_id": prs_icmp_udp_id})

        print("Create policy ruleset of TCP and UDP")
        prs_tcp_udp_id = self.create_gbp_policy_ruleset(gbp, "demo_ruleset_tcp_udp", rule_ids=[rule_tcp_id, rule_udp_id])
        policy_ruleset_ids.update({"tcp_udp_id": prs_tcp_udp_id})

        print("Create policy ruleset for all protocol")
        prs_all_id = self.create_gbp_policy_ruleset(gbp, "demo_ruleset_all", rule_ids=[rule_icmp_id, rule_tcp_id, rule_udp_id])
        policy_ruleset_ids.update({"allrule_id": prs_all_id})

        print("Create policy ruleset for no rule ")
        prs_norule_id = self.create_gbp_policy_ruleset(gbp, "demo_ruleset_norule")
        policy_ruleset_ids.update({"norule_id": prs_norule_id})

        return policy_ruleset_ids, policy_rules

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

    def create_external_networks_subnets(self, L3OUT1, L3OUT1_NET, L3OUT2, L3OUT2_NET):

        print "Create External Networks for L3Outs:: "+L3OUT1+" & "+L3OUT2+"\n"
        ext_net1 = self._admin_create_network(L3OUT1, {"shared": True, "router:external": True,
                                                         "apic:distinguished_names": {"ExternalNetwork": "uni/tn-common/out-"+L3OUT1+"/instP-"+L3OUT2_NET}})
        ext_sub1 = self._admin_create_subnet(ext_net1, {"cidr": '50.50.50.0/24', "enable_dhcp": False}, None)
        ext_sub2 = self._admin_create_subnet(ext_net1,
                                             {"cidr": '55.55.55.0/24', "enable_dhcp": False, "apic:snat_host_pool": True},
                                             None)
        ext_net2 = self._admin_create_network(L3OUT2, {"shared": True, "router:external": True,
                                                         "apic:distinguished_names": {"ExternalNetwork": "uni/tn-common/out-"+L3OUT2+"/instP-"+L3OUT2_NET}})
        ext_sub4 = self._admin_create_subnet(ext_net2, {"cidr": '55.55.55.0/24', "enable_dhcp": False, "apic:snat_host_pool": True}, None)

        return [ext_net1, ext_net2], [ext_sub1, ext_sub2, ext_sub4]

    def create_gbp_policy_rule_set_north_south(self, gbp):

        policy_ruleset_ids = {}
        policy_rules = {}
        print "START OF GBP NAT FUNCTIONALITY TESTSUITE GLOBAL CONFIG\n"
        print "Create a Policy Action needed for NAT Testing"
        self.create_gbp_policy_action(gbp, "ActAllow", **{"action_type": "allow", "shared": False})
        act_id = self.verify_gbp_policy_action(gbp, "ActAllow")
        print "Create a ICMP Policy Classifier and Rule needed for NAT Testing"
        cls_icmp_id, rule_icmp_id = self.create_gbp_classifier_and_policy_rule(
            gbp, act_id, "ClsIcmp", "icmp", "bi", "PrIcmp")
        policy_rules.update({"icmp_id": rule_icmp_id})
        print "Create a TCP Policy Classifier and Rule needed for NAT Testing"
        cls_tcp_id, rule_tcp_id = self.create_gbp_classifier_and_policy_rule(
            gbp, act_id, "ClsTcp", "tcp", "bi", "PrTcp", "20:2000")
        policy_rules.update({"tcp_id": rule_tcp_id})
        print "Create a ICMP-TCP Policy Rule Set needed for NAT Testing" 
        prs_icmp_tcp_id = self.create_gbp_policy_ruleset(gbp, "PrsIcmpTcp", rule_ids=[rule_icmp_id, rule_tcp_id])
        policy_ruleset_ids.update({"icmp_tcp_id": prs_icmp_tcp_id})
        print "Create a ICMP Policy Rule Set needed for NAT Testing"
        prs_icmp_id = self.create_gbp_policy_ruleset(gbp, "PrsIcmp", rule_ids=[rule_icmp_id])
        policy_ruleset_ids.update({"icmp_id": prs_icmp_id})
        print "Create a TCP Policy Rule Set needed for NAT Testing"
        prs_tcp_id = self.create_gbp_policy_ruleset(gbp, "PrsTcp", [rule_tcp_id])
        policy_ruleset_ids.update({"tcp_id": prs_tcp_id})

        return policy_ruleset_ids, policy_rules

    def verify_ns_gbp_object(self, gbp, defaultl3p, l3p, l2p, ext_seg, ip_pool, ext_pol, nat_pool, ptg, nat_type="dnat"):

        try:
            self.verify_gbp_any_object(gbp, "l3_policy", l3p,
                                       **{"external_segments": ext_seg, "l2_policies": l2p, "ip_pool": ip_pool})
            self.verify_gbp_any_object(gbp, "l2_policy", l2p, **{"l3_policy_id": l3p, "policy_target_groups": ptg})
            if nat_type == "dnat":
                self.verify_gbp_any_object(gbp, "external_segment", ext_seg,
                                       **{"l3_policies": [defaultl3p, l3p], "nat_pools": nat_pool,
                                          "external_policies": ext_pol})
            else:
                self.verify_gbp_any_object(gbp, "external_segment", ext_seg,
                                       **{"l3_policies": [defaultl3p, l3p], "external_policies": ext_pol})

        except Exception as e:
            print (e)
            raise TestError()

    def cleanup_ew(self, gbp):
        
        print "Cleaning up the setup after testing...\n"
        for vm in self.admin_clients("nova").servers.list():
            self._delete_server(vm)
            self.cleanup_gbp(gbp)
        for net in self.admin_clients("neutron").list_networks()["networks"]:
            self._delete_all_ports({"network":net})
            self._admin_delete_network({"network":net})

    def cleanup_ns(self, gbp):
        
        print "Global Config Clean-Up Initiated after testing\n"
        self.cleanup_floating_ip()
        for vm in self.admin_clients("nova").servers.list():
            self._delete_server(vm)
            self.cleanup_gbp(gbp)
        for net in self.admin_clients("neutron").list_networks()["networks"]:
            self._delete_all_ports({"network":net})
            self._admin_delete_network({"network":net})

