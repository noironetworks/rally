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
@scenario.configure(name="ScenarioPlugin.gbp_sanity", context={"cleanup@openstack": ["nova", "neutron"],
                    "keypair@openstack": {}, "allow_ssh@openstack": None}, platform="openstack")

class GBPSanity(create_resources.CreateResources, osutils.OSScenario, gbputils.GBPScenario, neutron_utils.NeutronScenario,
                nova_utils.NovaScenario, scenario.OpenStackScenario):

    def run(self, controller_ip, image, flavor, L3OUT1, L3OUT1_NET, L3OUT1_VRF, L3OUT2,
            L3OUT2_NET, L3OUT2_VRF, ext_rtr, extrtr_ip1, extrtr_ip2, dual_stack):

        print "\nCreate Openstack Tenant MANDRAKE for GBP\n"
        gbp_admin = self.gbp_client(controller_ip, "admin", "noir0123", "admin")
        pro1, user1, new_user = self.create_rally_client("MANDRAKE", "mandrake", self.context)
        self.context.get("users").append(new_user)
        self._change_client(1, self.context, None, None)
        gbp1 = self.gbp_client(controller_ip, "mandrake", "noir0123", "mandrake")

        print "Create Explicit L2Policies, Auto-PTGs & implicit L3Policy for Tenant MANDRAKE\n"
        l2p1, l2p1_impl3p, l2p1_autoptg, l2p1_nw = self.create_gbp_l2policy(gbp1, "L2P1", True, True)
        l2p2, l2p2_autoptg, l2p2_nw = self.create_gbp_l2policy(gbp1, "L2P2", False, True,
                                                               **{"l3_policy_id": l2p1_impl3p})

        print "Create Explicit PTG using L2P1 for Tenant MANDRAKE\n"
        reg_ptg = self.create_gbp_policy_target_group(gbp1, "REGPTG", **{"l2_policy_id": l2p1})

        print "Create Policy-Targets for two Auto-PTGs and one Regular PTG for Tenant MANDRAKE\n"
        pt1, port1 = self.create_gbp_policy_target(gbp1, "pt1", reg_ptg, 1, "uuid")
        pt2, port2 = self.create_gbp_policy_target(gbp1, "pt2", l2p1_autoptg, 1, "uuid")
        pt3, port3 = self.create_gbp_policy_target(gbp1, "pt3", l2p1_autoptg, 1, "uuid")
        pt4, port4 = self.create_gbp_policy_target(gbp1, "pt4", l2p2_autoptg, 1, "uuid")

        gbp_vm_nw_ip = [[0, 0, 0, 0], [0, 0]]
        gbp_vm_nw_ip[0] = [{"port": port1, "netns": "qdhcp-" + str(l2p1_nw), "tag": "intra_bd"},
                           {"port": port2, "netns": "qdhcp-" + str(l2p1_nw), "tag": "intra_epg"},
                           {"port": port3, "netns": "qdhcp-" + str(l2p1_nw), "tag": "intra_epg"},
                           {"port": port4, "netns": "qdhcp-" + str(l2p2_nw), "tag": "inter_bd"}, ]

        print "Create shared contracts and related resources in tenant-Admin\n"
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

        prs_tcp_id = self.create_gbp_policy_ruleset(gbp_admin, "CONT-TCP", rule_ids=[rule_tcp_id], shared=True)

        prs_list = {"CONT-ICMP-TCP": prs_icmp_tcp_id, "CONT-ICMP": prs_icmp_id, "CONT-TCP": prs_tcp_id}

        print "Create VMs for Tenant MANDRAKE\n"
        vm1 = self.boot_server(port1, image, flavor)
        vm2 = self.boot_server(port2, image, flavor)
        vm3 = self.boot_server(port3, image, flavor)
        vm4 = self.boot_server(port4, image, flavor)

        p1 = self._show_port({"port": {"id": port1}})
        p2 = self._show_port({"port": {"id": port2}})
        p3 = self._show_port({"port": {"id": port3}})
        p4 = self._show_port({"port": {"id": port4}})
        ip1 = p1.get('port', {}).get('fixed_ips')[0].get('ip_address')
        ip2 = p2.get('port', {}).get('fixed_ips')[0].get('ip_address')
        ip3 = p3.get('port', {}).get('fixed_ips')[0].get('ip_address')
        ip4 = p4.get('port', {}).get('fixed_ips')[0].get('ip_address')

        print "Create Shared External Network for ML2 Tenants\n"
        ext_net1, ext_sub1, ext_sub2 = self.create_external_network1(L3OUT1, L3OUT1_NET)
        print "Create External Segment as shared under tenant-Admin\n"
        ext_seg1 = self.create_gbp_external_segment(gbp_admin, L3OUT1,
                                                    **{"subnet_id": ext_sub1.get("subnet")["id"], "external_routes": [
                                                      {"destination": "0.0.0.0/0", "nexthop": None}], "shared": True})

        print "Create External Policy in tenant MANDRAKE\n"
        ext_pol1 = self.create_gbp_external_policy(gbp1, L3OUT1_NET, **{"external_segments": [ext_seg1]})
        print "Updating L3Policy to attach to External Segment in tenant MANDRAKE\n"
        self.update_gbp_l3policy(gbp1, l2p1_impl3p, "uuid", **{"external_segments": ext_seg1})
        self.update_gbp_external_policy(gbp1, ext_pol1, "uuid", [prs_icmp_tcp_id])
        self.update_gbp_policy_target_group(gbp1, reg_ptg, "uuid", None, [prs_icmp_tcp_id])

        print "Create & Attach FIP to VMs for the Tenant MANDRAKE\n"
        fip1 = self._attach_floating_ip(vm1, ext_net1.get("network"))
        fip2 = self._attach_floating_ip(vm2, ext_net1.get("network"))
        fip3 = self._attach_floating_ip(vm3, ext_net1.get("network"))
        fip4 = self._attach_floating_ip(vm4, ext_net1.get("network"))
        self.sleep_between(10, 15)

        command1 = self.command_for_start_http_server()
        command2 = self.command_for_icmp_tcp_traffic(ip1)
        command3 = self.command_for_icmp_tcp_traffic(ip2)
        command4 = self.command_for_icmp_tcp_traffic(ip3)
        command5 = self.command_for_icmp_tcp_traffic(ip4)
        command6 = self.command_for_stop_http_server()
        command7 = self.command_for_icmp_tcp_traffic(extrtr_ip1)
        command8 = self.command_for_icmp_tcp_traffic(extrtr_ip2)
        command9 = self.command_for_icmp_tcp_traffic_from_ext_rtr(fip1["ip"])
        command10 = self.command_for_icmp_tcp_traffic_from_ext_rtr(fip2["ip"])
        command11 = self.command_for_icmp_tcp_traffic_from_ext_rtr(fip3["ip"])
        command12 = self.command_for_icmp_tcp_traffic_from_ext_rtr(fip4["ip"])

        print "INTRA-EPG traffic between VMs in an AutoPTG MANDRAKE\n"
        print "Sending Traffic from VM2 in GBP-tenant MANDRAKE\n"
        self._remote_command("root", "noir0123", fip2["ip"], command1, vm2)
        self._remote_command("root", "noir0123", fip2["ip"], command4, vm2)
        self._remote_command("root", "noir0123", fip2["ip"], command6, vm2)
        print "Sending Traffic from VM3 in GBP-tenant MANDRAKE\n"
        self._remote_command("root", "noir0123", fip3["ip"], command1, vm3)
        self._remote_command("root", "noir0123", fip3["ip"], command3, vm3)
        self._remote_command("root", "noir0123", fip3["ip"], command6, vm3)

        print "Apply Contract PRS_ICMP_TCP between intra-BD EPGs by updation\n"
        self.update_intra_bd_ptg_by_contract(gbp1, reg_ptg, l2p1_autoptg, prs_icmp_tcp_id)
        print "INTRA-BD traffic between VMs across two EPGs\n"
        print "Sending Traffic from VM1 in GBP-tenant MANDRAKE\n"
        self._remote_command("root", "noir0123", fip1["ip"], command1, vm1)
        self._remote_command("root", "noir0123", fip1["ip"], command3, vm1)
        self._remote_command("root", "noir0123", fip1["ip"], command4, vm1)
        self._remote_command("root", "noir0123", fip1["ip"], command5, vm1)
        self._remote_command("root", "noir0123", fip1["ip"], command6, vm1)

        print "Apply Contract PRS_ICMP_TCP between inter-BD EPGs by updation\n"
        self.update_inter_bd_ptg_by_contract(gbp1, l2p2_autoptg, reg_ptg, l2p1_autoptg, prs_icmp_tcp_id)
        print "INTER-BD traffic between VMs across three EPGs\n"
        self._remote_command("root", "noir0123", fip4["ip"], command1, vm4)
        self._remote_command("root", "noir0123", fip4["ip"], command2, vm4)
        self._remote_command("root", "noir0123", fip4["ip"], command3, vm4)
        self._remote_command("root", "noir0123", fip4["ip"], command4, vm4)
        self._remote_command("root", "noir0123", fip4["ip"], command6, vm4)

        print "Apply ICMP&TCP contract to all Private & External EPGs in tenant MANDRAKE\n"
        self.update_gbp_external_policy(gbp1, ext_pol1, "uuid", [prs_icmp_tcp_id])
        self.update_gbp_policy_target_group(gbp1, reg_ptg, "uuid", None, [prs_icmp_tcp_id])
        self.update_gbp_policy_target_group(gbp1, l2p1_autoptg, "uuid", None, [prs_icmp_tcp_id])
        self.update_gbp_policy_target_group(gbp1, l2p2_autoptg, "uuid", None, [prs_icmp_tcp_id])
        self.sleep_between(15, 20)

        print "SNAT Traffic from MANDRAKE VMs to External Router\n"
        print "Sending Traffic from VM2 in GBP-tenant MANDRAKE\n"
        self._remote_command("root", "noir0123", fip2["ip"], command7, vm2)
        self._remote_command("root", "noir0123", fip2["ip"], command8, vm2)
        print "Sending Traffic from VM3 in GBP-tenant MANDRAKE\n"
        self._remote_command("root", "noir0123", fip3["ip"], command7, vm3)
        self._remote_command("root", "noir0123", fip3["ip"], command8, vm3)

        print "Sending ICMP/TCP Traffic from EXT-RTR to VMs\n"
        self._remote_command_wo_server("noiro", "noir0123", ext_rtr, command9)
        self._remote_command_wo_server("noiro", "noir0123", ext_rtr, command10)
        self._remote_command_wo_server("noiro", "noir0123", ext_rtr, command11)
        self._remote_command_wo_server("noiro", "noir0123", ext_rtr, command12)

        print("Create Openstack Tenant BATMAN for GBP\n")
        pro2, user2, new_user = self.create_rally_client("BATMAN", "batman", self.context)
        self.context.get("users").append(new_user)
        self._change_client(2, self.context, None, None)
        gbp2 = self.gbp_client(controller_ip, "batman", "noir0123", "batman")

        print "Create Address Scope, Explicit L3Policy, L2Policy for Tenant BATMAN\n"
        asc1 = self.create_address_scope("nonat_ads", "4", True, True, **{
            "apic:distinguished_names": {"VRF": "uni/tn-common/ctx-"+L3OUT2_VRF}})
        subpool1 = self.create_subnet_pool("nonat_sps", asc1.get("address_scope")["id"], "60.60.60.0/24", "28", True, True)

        l3p = self.create_gbp_l3policy(gbp2, "L3P1", **{"subnetpools_v4": [subpool1.get("subnetpool")["id"]]})
        l2p3, l2p3_autoptg, l2p3_nw = self.create_gbp_l2policy(gbp2, "L2P3", False, True, **{"l3_policy_id": l3p})

        print "Create Two Policy-Targets from an Auto-PTGs for Tenant BATMAN\n"
        pt5, port5 = self.create_gbp_policy_target(gbp2, "pt5", l2p3_autoptg, 1, "uuid")
        pt6, port6 = self.create_gbp_policy_target(gbp2, "pt6", l2p3_autoptg, 1, "uuid")

        gbp_vm_nw_ip[1] = [{"port": port5, "netns": "qdhcp-" + str(l2p3_nw), "tag": "intra_epg"},
                           {"port": port6, "netns": "qdhcp-" + str(l2p3_nw), "tag": "intra_epg"}]

        print "Create VMs for Tenant BATMAN\n"
        vm5 = self.boot_server(port5, image, flavor)
        vm6 = self.boot_server(port6, image, flavor)

        print "Create Shared External Network for ML2 Tenants\n"
        ext_net2, ext_sub3 = self.create_external_network2(L3OUT2, L3OUT2_NET)

        print "Create External Segment as shared under tenant-Admin\n"
        ext_seg2 = self.create_gbp_external_segment(gbp_admin, L3OUT2,
                                                    **{"subnet_id": ext_sub3.get("subnet")["id"], "external_routes": [
                                                        {"destination": "0.0.0.0/0", "nexthop": None}], "shared": True})

        print "Create External Policy in tenant BATMAN\n"
        ext_pol2 = self.create_gbp_external_policy(gbp2, L3OUT2_NET, **{"external_segments": [ext_seg2]})
        print "Updating L3Policy in tenant BATMAN to attach to ExtSegments\n"
        self.update_gbp_l3policy(gbp2, l3p, "uuid", **{"external_segments": ext_seg2})
        print "Apply contract on ExtPol & AutoPtg got NoNAT\n"
        self.update_gbp_external_policy(gbp2, ext_pol2, "uuid", [prs_icmp_tcp_id])
        self.update_gbp_policy_target_group(gbp2, l2p3_autoptg, "uuid", None, [prs_icmp_tcp_id])

        p5 = self._show_port({"port": {"id": port5}})
        p6 = self._show_port({"port": {"id": port6}})
        ip5 = p5.get('port', {}).get('fixed_ips')[0].get('ip_address')
        ip6 = p6.get('port', {}).get('fixed_ips')[0].get('ip_address')

        print "NoNAT Traffic from BATMAN VMs to External Router\n"
        print "Sending Traffic from VM5 in GBP-tenant BATMAN\n"
        self._remote_command("root", "noir0123", ip5, command1, vm5)
        self._remote_command("root", "noir0123", ip5, command7, vm5)
        self._remote_command("root", "noir0123", ip5, command8, vm5)
        self._remote_command("root", "noir0123", ip5, command6, vm5)
        print "Sending Traffic from VM6 in GBP-tenant BATMAN\n"
        self._remote_command("root", "noir0123", ip6, command1, vm6)
        self._remote_command("root", "noir0123", ip6, command7, vm6)
        self._remote_command("root", "noir0123", ip6, command8, vm6)
        self._remote_command("root", "noir0123", ip6, command6, vm6)

        print "cleaning up the setup after testing\n"
        for item in [vm5, vm6]:
            self._delete_server(item)
        for i, j in [(vm1,fip1), (vm2,fip2), (vm3,fip3), (vm4,fip4)]:
            self._delete_floating_ip(i, j)
            self._delete_server(i)
        self.cleanup_gbp(gbp_admin)
        self.delete_subnet_pool(subpool1.get("subnetpool")["id"])
        self.delete_address_scope(asc1.get("address_scope")["id"])
        self._admin_delete_network(ext_net1)
        self._admin_delete_network(ext_net2)
        for item in [user1, user2]:
            self._delete_user(item)
        for item in [pro1, pro2]:
            self._delete_project(item)

    def update_intra_bd_ptg_by_contract(self, gbp, ptg1, ptg2, rule_set_id):

        self.update_gbp_policy_target_group(gbp, ptg1, "uuid", "", [rule_set_id])
        self.update_gbp_policy_target_group(gbp, ptg2, "uuid", [rule_set_id])
        self.sleep_between(10, 15)

    def update_inter_bd_ptg_by_contract(self, gbp, ptg1, ptg2, ptg3, rule_set_id):

        self.update_gbp_policy_target_group(gbp, ptg1, "uuid", "", [rule_set_id])
        self.update_gbp_policy_target_group(gbp, ptg2, "uuid", [rule_set_id], "")
        self.update_gbp_policy_target_group(gbp, ptg3, "uuid", [rule_set_id], "")