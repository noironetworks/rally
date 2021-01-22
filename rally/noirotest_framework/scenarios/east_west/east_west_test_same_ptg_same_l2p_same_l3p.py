from rally import consts
from rally.common import validation
from rally.plugins.openstack import scenario
from rally.noirotest_framework import osutils
from rally.noirotest_framework import gbputils
from rally.noirotest_framework import create_resources
from rally.plugins.openstack.scenarios.nova import utils as nova_utils
from rally.plugins.openstack.scenarios.neutron import utils as neutron_utils


@validation.add("required_services", services=[consts.Service.NOVA, consts.Service.NEUTRON])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(name="ScenarioPlugin.east_west_test_same_ptg_same_l2p_same_l3p",
                    context={"cleanup@openstack": ["nova", "neutron"], "keypair@openstack": {},
                    "allow_ssh@openstack": None}, platform="openstack")

class EastWest(create_resources.CreateResources, osutils.OSScenario, gbputils.GBPScenario,
               neutron_utils.NeutronScenario, nova_utils.NovaScenario, scenario.OpenStackScenario):

    def run(self, controller_ip, image, flavor, L3OUT1, L3OUT1_NET, extrtr_net1, nova_az, plugin_type):

        try:
            created_resources={}
            gbp = self.gbp_client(controller_ip, "admin", "noir0123", "admin")

            policy_rule_set, policy_rules = self.create_gbp_policy_rule_set_east_west(gbp)

            l3p = self.create_gbp_l3policy(gbp, "demo_same_ptg_l2p_l3p",
                                           **{"ip_pool": "5.5.5.0/24", "subnet_prefix_length": "28"})
            l2p = self.create_gbp_l2policy(gbp, "demo_same_ptg_l2p_l3p_bd", False, False, **{"l3_policy_id": l3p})
            ptg = self.create_gbp_policy_target_group(gbp, "demo_same_ptg_l2p_l3p_ptg", **{"l2_policy_id": l2p})

            pt1, port1 = self.create_gbp_policy_target(gbp, "vm1_data_pt", "demo_same_ptg_l2p_l3p_ptg", 1)
            pt2, port2 = self.create_gbp_policy_target(gbp, "vm2_data_pt", "demo_same_ptg_l2p_l3p_ptg", 1)
            pt3, port3 = self.create_gbp_policy_target(gbp, "vm3_data_pt", "demo_same_ptg_l2p_l3p_ptg", 1)

            print "Create Shared External Network as Management network\n"
            ext_net1 = self._admin_create_network(L3OUT1, {"shared": True, "router:external": True,
                                                             "apic:distinguished_names": {"ExternalNetwork": "uni/tn-common/out-"+L3OUT1+"/instP-"+L3OUT1_NET}})
            ext_sub1 = self._admin_create_subnet(ext_net1, {"cidr": '50.50.50.0/28', "enable_dhcp": True}, None)
            created_resources["networks"]=[ext_net1]

            port_create_args = {}
            port_create_args.update({"port_security_enabled": "false"})
            pfip = self._admin_create_port(ext_net1, port_create_args)
            pfip_id = pfip.get('port', {}).get('id')
            nics = [{"port-id": pfip_id}, {"port-id": port1}]
            kwargs = {}
            kwargs.update({'nics': nics})
            kwargs.update({"availability_zone": nova_az})
            vm1 = self._admin_boot_server(image, flavor, "VM1", False, **kwargs)
            created_resources["vms"]=[vm1]

            vm2 = self.admin_boot_server(port2, image, flavor, "VM2", **{"availability_zone": nova_az})
            created_resources["vms"].append(vm2)
            vm3 = self.admin_boot_server(port3, image, flavor, "VM3")
            created_resources["vms"].append(vm3)

            fip = pfip.get('port', {}).get('fixed_ips')[0].get('ip_address')
            ip2 = self._admin_show_port({"port": {"id": port2}}).get('port', {}).get('fixed_ips')[0].get('ip_address')
            ip3 = self._admin_show_port({"port": {"id": port3}}).get('port', {}).get('fixed_ips')[0].get('ip_address')

            print "Configuring multi-interface in VM\n"
            command0 = self.command_for_vm_config_with_route(extrtr_net1)
            self._remote_command("root", "noir0123", fip, command0, vm1)

            print("Traffic verification for same_host\n")
            for flag in ['enforced', 'unenforced']:
                print "Run the Intra-EPG TestSuite with %s" %(flag)
                if flag == 'enforced':
                    if plugin_type:
                        self.update_gbp_policy_target_group(gbp, ptg, "uuid", **{"intra_ptg_allow": False})
                        self.sleep_between(5, 7)
                    else:
                        #####################################################
                        # add enforced to ptg
                        #########################
                        pass
                    print "Expected traffic verification should FAIL\n"
                else:
                    if plugin_type:
                        self.update_gbp_policy_target_group(gbp, ptg, "uuid", **{"intra_ptg_allow": True})
                        self.sleep_between(5, 7)
                    else:
                        #####################################################
                        # add enforced to ptg
                        #########################
                        pass
                    print "Expected traffic verification should PASS\n"

                self.update_ptg_with_no_prs()
                self.verify_traffic(fip, vm1, ip2)
                self.update_ptg_with_no_rule(gbp, ptg, policy_rule_set)
                self.verify_traffic(fip, vm1, ip2)
                self.update_ptg_with_icmp(gbp, ptg, policy_rule_set)
                self.verify_traffic(fip, vm1, ip2)
                self.update_ptg_with_tcp(gbp, ptg, policy_rule_set)
                self.verify_traffic(fip, vm1, ip2)
                self.update_ptg_with_icmp_tcp(gbp, ptg, policy_rule_set)
                self.verify_traffic(fip, vm1, ip2)
                self.update_ptg_with_icmp_udp(gbp, ptg, policy_rule_set)
                self.verify_traffic(fip, vm1, ip2)
                self.update_ptg_with_all_proto(gbp, ptg, policy_rule_set)
                self.verify_traffic(fip, vm1, ip2)
                self.update_ptg_with_rem_prs(gbp, ptg)
                self.verify_traffic(fip, vm1, ip2)

            print("Traffic verification for diff_host_diff_leaf\n")
            for flag in ['enforced', 'unenforced']:
                print "Run the Intra-EPG TestSuite with %s" %(flag)
                if flag == 'enforced':
                    if plugin_type:
                        self.update_gbp_policy_target_group(gbp, ptg, "uuid", **{"intra_ptg_allow": False})
                    else:
                        #####################################################
                        # add enforced to ptg
                        #########################
                        pass
                    print "Expected traffic verification should FAIL\n"
                else:
                    if plugin_type:
                        self.update_gbp_policy_target_group(gbp, ptg, "uuid", **{"intra_ptg_allow": True})
                    else:
                        #####################################################
                        # add enforced to ptg
                        #########################
                        pass
                    print "Expected traffic verification should PASS\n"

                self.update_ptg_with_no_prs()
                self.verify_traffic(fip, vm1, ip3)
                self.update_ptg_with_no_rule(gbp, ptg, policy_rule_set)
                self.verify_traffic(fip, vm1, ip3)
                self.update_ptg_with_icmp(gbp, ptg, policy_rule_set)
                self.verify_traffic(fip, vm1, ip3)
                self.update_ptg_with_tcp(gbp, ptg, policy_rule_set)
                self.verify_traffic(fip, vm1, ip3)
                self.update_ptg_with_icmp_tcp(gbp, ptg, policy_rule_set)
                self.verify_traffic(fip, vm1, ip3)
                self.update_ptg_with_icmp_udp(gbp, ptg, policy_rule_set)
                self.verify_traffic(fip, vm1, ip3)
                self.update_ptg_with_all_proto(gbp, ptg, policy_rule_set)
                self.verify_traffic(fip, vm1, ip3)
                self.update_ptg_with_rem_prs(gbp, ptg)
                self.verify_traffic(fip, vm1, ip3)
        except Exception as e:
            raise e
        finally:
            self.cleanup_ew(gbp)

    def update_ptg_with_no_prs(self):

        print "\nTest_1_Traff_With_No_PRS: 10 Traffic Sub-Testcases with NO CONTRACT for arp,dns,dhcp,tcp,udp,icmp and their combos\n"

    def update_ptg_with_no_rule(self, gbp, ptg, prs_ids):

        print "Test_2_Traff_Apply_PRS_No_Rule: 10 Traffic Sub-Testcases with CONTRACT But NO RULE for arp,dns,dhcp,tcp,udp,icmp and their combos\n"
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", [prs_ids["norule_id"]], [prs_ids["norule_id"]])
        self.sleep_between(5, 7)

    def update_ptg_with_icmp(self, gbp, ptg, prs_ids):

        print "Test_3_Traff_Apply_PRS_ICMP: Apply ICMP CONTRACT and Verify Traffic\n"
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", [prs_ids["icmp_id"]], [prs_ids["icmp_id"]])
        self.sleep_between(5, 7)

    def update_ptg_with_tcp(self, gbp, ptg, prs_ids):

        print "Test_4_Traff_Apply_PRS_TCP: Apply TCP CONTRACT and Verify Traffic\n"
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", [prs_ids["tcp_id"]], [prs_ids["tcp_id"]])
        self.sleep_between(5, 7)

    def update_ptg_with_icmp_tcp(self, gbp, ptg, prs_ids):

        print "Test_5_Traff_Apply_PRS_ICMP_TCP: Apply ICMP-TCP combo CONTRACT and Verify Traffic\n"
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", [prs_ids["icmp_tcp_id"]], [prs_ids["icmp_tcp_id"]])
        self.sleep_between(5, 7)

    def update_ptg_with_icmp_udp(self, gbp, ptg, prs_ids):

        print "Test_6_Traff_Apply_PRS_ICMP_UDP: Apply ICMP-UDP combo CONTRACT and Verify Traffic\n"
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", [prs_ids["icmp_udp_id"]], [prs_ids["icmp_udp_id"]])
        self.sleep_between(5, 7)

    def update_ptg_with_all_proto(self, gbp, ptg, prs_ids):

        print "Test_7_Traff_Apply_PRS_All_Proto: Apply ICMP-TCP-UDP combo CONTRACT and Verify Traffic\n"
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", [prs_ids["allrule_id"]], [prs_ids["allrule_id"]])
        self.sleep_between(5, 7)

    def update_ptg_with_rem_prs(self, gbp, ptg):

        print "Test_8_Traff_Rem_PRS: 10 Traffic Sub-Testcases REMOVE CONTRACT for arp,dns,dhcp,tcp,udp,icmp and their combos\n"
        self.update_gbp_policy_target_group(gbp, ptg, "uuid", "", "")
        self.sleep_between(5, 7)

    def verify_traffic(self, fip, vm, dest_ip):

        command1 = self.command_for_start_http_server()
        command2 = self.command_for_icmp_traffic(dest_ip)
        command3 = self.command_for_tcp_traffic(dest_ip)
        command4 = self.command_for_udp_traffic(dest_ip)
        command5 = self.command_for_stop_http_server()
        self._remote_command("root", "noir0123", fip, command1, vm)
        self._remote_command("root", "noir0123", fip, command2, vm)
        self._remote_command("root", "noir0123", fip, command3, vm)
        self._remote_command("root", "noir0123", fip, command4, vm)
        self._remote_command("root", "noir0123", fip, command5, vm)

