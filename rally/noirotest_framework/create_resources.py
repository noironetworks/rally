import copy
import json
from rally import exceptions
from rally.task import utils
from rally.common import cfg
from rally.task import atomic
from rally.common import logging
from rally.common import sshutils
from rally.plugins.openstack import scenario
from rally.plugins.openstack import osclients
from rally.plugins.openstack.scenarios.vm import utils as vm_utils
from rally.plugins.openstack.scenarios.nova import utils as nova_utils
from rally.plugins.openstack.wrappers import network as network_wrapper
from rally.plugins.openstack.scenarios.neutron import utils as neutron_utils

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class OSScenario(vm_utils.VMScenario, neutron_utils.NeutronScenario, nova_utils.NovaScenario,
                 scenario.OpenStackScenario):

    def _get_domain_id(self, domain_name_or_id):

        domains = self._admin_clients.keystone("3").domains.list(
            name=domain_name_or_id)

        return domains[0].id

    @atomic.action_timer("keystone_v3.create_project")
    def _create_project(self, project_name, domain_name):

        project_name = project_name or self.generate_random_name()
        domain_id = self._get_domain_id(domain_name)

        return self._admin_clients.keystone("3").projects.create(name=project_name,
                                                                 domain=domain_id)

    @atomic.action_timer("keystone_v3.delete_project")
    def _delete_project(self, project_id):

        self._admin_clients.keystone("3").projects.delete(project_id)

    @atomic.action_timer("keystone_v3.add_role")
    def _add_role(self, role_name, user_id, project_id):

        role_id = self._admin_clients.keystone("3").roles.list(name=role_name)[0].id
        self._admin_clients.keystone("3").roles.grant(role=role_id,
                                                      user=user_id,
                                                      project=project_id)

    @atomic.action_timer("keystone_v3.create_user")
    def _create_user(self, username, password, project_id, domain_name, enabled=True,
                     default_role="Admin"):

        domain_id = self._get_domain_id(domain_name)
        username = username or self.generate_random_name()
        user = self._admin_clients.keystone("3").users.create(
            name=username, password=password, default_project=project_id,
            domain=domain_id, enabled=enabled)

        for usr in self._admin_clients.keystone("3").users.list():
            if usr.name == 'admin':
                admin_id = usr.id

        if project_id:
            # we can't setup role without project_id

            self._add_role(default_role, user_id=user.id,
                           project_id=project_id)
            self._add_role(default_role, user_id=admin_id, project_id=project_id)
        return user

    @atomic.action_timer("keystone_v3.delete_user")
    def _delete_user(self, user):

        self._admin_clients.keystone("3").users.delete(user)

    @atomic.action_timer("change_user")
    def _change_client(self, pos, context=None, admin_clients=None, clients=None):

        if context:
            api_info = {}
            if "api_versions@openstack" in context.get("config", {}):
                api_versions = context["config"]["api_versions@openstack"]
                for service in api_versions:
                    api_info[service] = {
                        "version": api_versions[service].get("version"),
                        "service_type": api_versions[service].get(
                            "service_type")}

            if admin_clients is None and "admin" in context:
                self._admin_clients = osclients.Clients(
                    context["admin"]["credential"], api_info)
            if clients is None:
                if "users" in context and "user" not in context:
                    self._choose_user(context)

                if "user" in context:
                    self._clients = osclients.Clients(context["users"][pos]["credential"], api_info)

        if admin_clients:
            self._admin_clients = admin_clients

        if clients:
            self._clients = clients

    @atomic.action_timer("nova.admin_boot_server")
    def _admin_boot_server(self, image, flavor, name,
                           auto_assign_nic=False, **kwargs):

        server_name = name

        if auto_assign_nic and not kwargs.get("nics", False):
            nic = self._pick_random_nic()
            if nic:
                kwargs["nics"] = nic

        server = self.admin_clients("nova").servers.create(
            server_name, image, flavor, **kwargs)

        self.sleep_between(CONF.openstack.nova_server_boot_prepoll_delay)
        server = utils.wait_for_status(
            server,
            ready_statuses=["ACTIVE"],
            update_resource=utils.get_from_manager(),
            timeout=CONF.openstack.nova_server_boot_timeout,
            check_interval=CONF.openstack.nova_server_boot_poll_interval
        )
        return server

    @atomic.action_timer("neutron.admin_create_network")
    def _admin_create_network(self, name, network_create_args):

        network_create_args["name"] = name
        return self.admin_clients("neutron").create_network(
            {"network": network_create_args})

    @atomic.action_timer("neutron.admin_delete_network")
    def _admin_delete_network(self, network):

        self.admin_clients("neutron").delete_network(network["network"]["id"])

    @atomic.action_timer("neutron.admin_create_subnet")
    def _admin_create_subnet(self, network, subnet_create_args, start_cidr=None):

        network_id = network["network"]["id"]

        if not subnet_create_args.get("cidr"):
            start_cidr = start_cidr or "10.2.0.0/24"
            subnet_create_args["cidr"] = (
                network_wrapper.generate_cidr(start_cidr=start_cidr))

        subnet_create_args["network_id"] = network_id
        subnet_create_args["name"] = self.generate_random_name()
        subnet_create_args.setdefault("ip_version", self.SUBNET_IP_VERSION)

        return self.admin_clients("neutron").create_subnet(
            {"subnet": subnet_create_args})

    @atomic.action_timer("neutron.admin_create_port")
    def _admin_create_port(self, network, port_create_args):

        port_create_args["network_id"] = network["network"]["id"]
        port_create_args["name"] = self.generate_random_name()
        return self.admin_clients("neutron").create_port({"port": port_create_args})

    @atomic.action_timer("neutron.admin_show_port")
    def _admin_show_port(self, port, **params):

       return self.admin_clients("neutron").show_port(port["port"]["id"], **params)

    @atomic.action_timer("neutron.admin_delete_port")
    def _admin_delete_port(self, port):

        self.admin_clients("neutron").delete_port(port["port"]["id"])

    @atomic.action_timer("delete_all_ports")
    def _delete_all_ports(self, network):

        port_list = self.admin_clients("neutron").list_ports()["ports"]
        for port in port_list:
            if port['network_id'] == network["network"]["id"]:
                self.admin_clients("neutron").delete_port(port["id"])

    @atomic.action_timer("neutron.delete_router")
    def _admin_delete_router(self, router):

        self.admin_clients("neutron").delete_router(router["router"]["id"])

    @atomic.action_timer("neutron.admin_remove_interface_router")
    def _admin_remove_interface_router(self, subnet, router):

        self.admin_clients("neutron").remove_interface_router(
            router["router"]["id"], {"subnet_id": subnet["subnet"]["id"]})

    @atomic.action_timer("nova.user_boot_server")
    def _user_boot_server(self, image, flavor,
                          auto_assign_nic=False, **kwargs):

        server_name = self.generate_random_name()
        if "security_groups" not in kwargs:
                kwargs["security_groups"] = ["default"]
        elif secgroup["name"] not in kwargs["security_groups"]:
                kwargs["security_groups"].append("default")

        if auto_assign_nic and not kwargs.get("nics", False):
            nic = self._pick_random_nic()
            if nic:
                kwargs["nics"] = nic

        server = self.clients("nova").servers.create(
            server_name, image, flavor, **kwargs)

        self.sleep_between(CONF.openstack.nova_server_boot_prepoll_delay)
        server = utils.wait_for_status(
            server,
            ready_statuses=["ACTIVE"],
            update_resource=utils.get_from_manager(),
            timeout=CONF.openstack.nova_server_boot_timeout,
            check_interval=CONF.openstack.nova_server_boot_poll_interval
        )
        return server

    @atomic.action_timer("neutron.create_address_scope")
    def create_address_scope(self, name, ip_version, shared=False, admin=False, **kwargs):
        """
                Create an Address Scope
                """
        address_scope = {"name": name, "ip_version": ip_version, "shared": shared}
        for arg, val in kwargs.items():
            address_scope[arg] = val
        body = {"address_scope": address_scope}
        if admin:
            return self.admin_clients("neutron").create_address_scope(body)
        else:
            return self.clients("neutron").create_address_scope(body)

    @atomic.action_timer("neutron.delete_address_scope")
    def delete_address_scope(self, addscope_id):

        self.admin_clients("neutron").delete_address_scope(addscope_id)

    @atomic.action_timer("neutron.create_subnet_pool")
    def create_subnet_pool(self, name, add_scope, prefixes, def_prefixlen, shared=False, admin=False, **kwargs):
        """
                Create an Address Scope
                """
        subnet_pool = {"name": name, "address_scope_id": add_scope, "prefixes": [prefixes],
                       "default_prefixlen": def_prefixlen, "shared": shared}
        for arg, val in kwargs.items():
            subnet_pool[arg] = val
        body = {"subnetpool": subnet_pool}
        if admin:
            return self.admin_clients("neutron").create_subnetpool(body)
        else:
            return self.clients("neutron").create_subnetpool(body)

    @atomic.action_timer("neutron.delete_subnet_pool")
    def delete_subnet_pool(self, subpool_id):

        self.admin_clients("neutron").delete_subnetpool(subpool_id)

    def create_subnet_with_pool(self, network, subnet_create_args, start_cidr=None):

        """Create neutron subnet from pool.
        :param network: neutron network dict
        :param subnet_create_args: POST /v2.0/subnets request options
        :returns: neutron subnet dict
        """
        network_id = network["network"]["id"]

        subnet_create_args["network_id"] = network_id
        subnet_create_args["name"] = self.generate_random_name()

        return self.clients("neutron").create_subnet(
            {"subnet": subnet_create_args})

    def install_secgroup_rules(self, secgroup, default_route='0.0.0.0/0'):

        sec_id = secgroup.get("security_group").get("id")
        self._create_security_group_rule(sec_id, **{"protocol": "icmp", "direction": "ingress", "remote_ip_prefix": default_route})
        self._create_security_group_rule(sec_id, **{"protocol": "tcp", "direction": "ingress", "remote_ip_prefix": default_route,
                                                  "port_range_min": "22", "port_range_max": "22"})
        self._create_security_group_rule(sec_id, **{"protocol": "tcp", "direction": "ingress", "remote_ip_prefix": default_route,
                                                  "port_range_min": "80", "port_range_max": "80"})

    def boot_server(self, port, image, flavor):

        nics = [{"port-id": port}]
        kwargs = {}
        kwargs.update({'nics': nics})
        vm = self._user_boot_server(image, flavor, False, **kwargs)
        self.sleep_between(10, 15)
        return vm

    def admin_boot_server(self, port, image, flavor, name, **kwargs):

        nics = [{"port-id": port}]
        kwargs.update({'nics': nics})
        vm = self._admin_boot_server(image, flavor, name, False, **kwargs)
        self.sleep_between(10, 15)
        return vm

    def create_rally_client(self, pro_name, username, context):

        pro = self._create_project(pro_name, 'default')
        user = self._create_user(username, 'noir0123', pro.id, "default", True, "Admin")
        dic = copy.deepcopy(context)
        new_user = dic.get("users")[0]
        new_user.get("credential").update({'username': username, 'tenant_name': username, 'password': 'noir0123'})
        return pro, user, new_user

    def get_secgroup(self, pro_id):

        for sec in self._list_security_groups().get("security_groups"):
            if sec.get("tenant_id")==pro_id:
                return {"security_group": sec}

    def create_external_network1(self, L3OUT1, L3OUT1_NET):

        ext_net1 = self._admin_create_network(L3OUT1, {"shared": True, "router:external": True,
                                                         "apic:distinguished_names": {"ExternalNetwork": "uni/tn-common/out-"+L3OUT1+"/instP-"+L3OUT1_NET}})
        ext_sub1 = self._admin_create_subnet(ext_net1, {"cidr": '50.50.50.0/28', "enable_dhcp": False}, None)
        ext_sub2 = self._admin_create_subnet(ext_net1,
                                             {"cidr": '55.55.55.0/28', "enable_dhcp": False, "apic:snat_host_pool": True},
                                             None)
        return ext_net1, ext_sub1, ext_sub2

    def create_external_network2(self, L3OUT2, L3OUT2_NET):

        ext_net2 = self._admin_create_network(L3OUT2, {"shared": True, "router:external": True,
                                                         "apic:distinguished_names": {"ExternalNetwork": "uni/tn-common/out-"+L3OUT2+"/instP-"+L3OUT2_NET},
                                                         "apic:nat_type": ""})
        ext_sub3 = self._admin_create_subnet(ext_net2, {"cidr": '2.3.4.0/24', "enable_dhcp": False}, None)
        return ext_net2, ext_sub3

    def command_for_start_http_server(self):

        command = {
                    "interpreter": "/bin/sh",
                    "script_inline": """nohup python -m SimpleHTTPServer 80 & " ";echo 'Starting SimpleHTTPServer on port 80'"""
                }
        return command

    def command_for_stop_http_server(self):

        command = {
                    "interpreter": "/bin/sh",
                    "script_inline": """kill -9 $(ps -ef | grep [S]imple | awk -F" " '{print $2}');echo 'Stopping SimpleHTTPServer on port 80'"""
                }
        return command

    def command_for_icmp_tcp_traffic(self, dest_ip):

        command = {
                    "interpreter": "/bin/sh",
                    "script_inline": "hping3 "+dest_ip+" --icmp -c 5 --fast -q -d 1000; nc -w 1 -v "+dest_ip+" -z 22"
                }
        return command

    def command_for_icmp_tcp_traffic_from_ext_rtr(self, dest_ip):

        command = {
                    "interpreter": "/bin/sh",
                    "script_inline": "ping "+dest_ip+" -c 5 -i 0.2 -W 1 -s 1000; nc -w 1 -v "+dest_ip+" -z 22"
                }
        return command

    def command_for_icmp_traffic(self, dest_ip):

        command = {
                    "interpreter": "/bin/sh",
                    "script_inline": "hping3 "+dest_ip+" --icmp -c 5 --fast -q -d 1000"
                }
        return command

    def command_for_tcp_traffic(self, dest_ip):

        command = {
                    "interpreter": "/bin/sh",
                    "script_inline": "hping3 "+dest_ip+" -S -V -p 80 -c 5 --fast -q --tcp-timestamp;\
                                      hping3 "+dest_ip+" -S -A -V -p 80 -c 5 --fast -q --tcp-timestamp;\
                                      hping3 "+dest_ip+" -S -A -F -V -p 80 -c 5 --fast -q --tcp-timestamp"
                }
        return command

    def command_for_udp_traffic(self, dest_ip):

        command = {
                    "interpreter": "/bin/sh",
                    "script_inline": "hping3 "+dest_ip+" --udp -p 80 -c 5 --fast -q"
                }
        return command

    def command_for_vm_config(self):

        command = {
                    "interpreter": "/bin/sh",
                    "script_inline": "dhclient eth1"
                }
        return command

    def command_to_add_route(self, dest_nw, gw):

        command = {
                    "interpreter": "/bin/sh",
                    "script_inline": "ip route add "+dest_nw+" via "+gw+" dev eth1"
                }
        return command

    @atomic.action_timer("run_remote_command")
    def _remote_command(self, username, password, fip, command, server, **kwargs):

        port=22
        wait_for_ping=True
        max_log_length=None

        try:
            if wait_for_ping:
                self._wait_for_ping(fip)

            code, out, err = self._run_command(
                fip, port, username, password, command=command)

            print out

            text_area_output = ["StdOut:"]

            if code:
                print exceptions.ScriptError(
                    "Error running command %(command)s. "
                    "Error %(code)s: %(error)s" % {
                        "command": command, "code": code, "error": err})
                print "------------------------------"
            else:
                print "------------------------------"
            # Let's try to load output data
            try:
                data = json.loads(out)
                if not isinstance(data, dict):
                    raise ValueError
            except ValueError:
                # It's not a JSON, probably it's 'script_inline' result
                data = []
        except (exceptions.TimeoutException,
                exceptions.SSHTimeout):
            console_logs = self._get_server_console_output(server,
                                                           max_log_length)
            LOG.debug("VM console logs:\n%s" % console_logs)
            raise

        if isinstance(data, dict) and set(data) == {"additive", "complete"}:
            for chart_type, charts in data.items():
                for chart in charts:
                    self.add_output(**{chart_type: chart})
        else:
            # it's a dict with several unknown lines
            text_area_output.extend(out.split("\n"))
            self.add_output(complete={"title": "Script Output",
                                      "chart_plugin": "TextArea",
                                      "data": text_area_output})

    @atomic.action_timer("run_remote_command_wo_server")
    def _remote_command_wo_server(self, username, password, fip, command, **kwargs):

        port=22
        wait_for_ping=True
        max_log_length=None

        try:
            if wait_for_ping:
                self._wait_for_ping(fip)

            code, out, err = self._run_command(
                fip, port, username, password, command=command)

            print out

            text_area_output = ["StdOut:"]

            if code:
                print exceptions.ScriptError(
                    "Error running command %(command)s. "
                    "Error %(code)s: %(error)s" % {
                        "command": command, "code": code, "error": err})
                print "------------------------------"
            else:
                print "------------------------------"
            # Let's try to load output data
            try:
                data = json.loads(out)
                if not isinstance(data, dict):
                    raise ValueError
            except ValueError:
                # It's not a JSON, probably it's 'script_inline' result
                data = []
        except (exceptions.TimeoutException,
                exceptions.SSHTimeout):
            raise

        if isinstance(data, dict) and set(data) == {"additive", "complete"}:
            for chart_type, charts in data.items():
                for chart in charts:
                    self.add_output(**{chart_type: chart})
        else:
            # it's a dict with several unknown lines
            text_area_output.extend(out.split("\n"))
            self.add_output(complete={"title": "Script Output",
                                      "chart_plugin": "TextArea",
                                      "data": text_area_output})

class TestError(Exception):
    pass
(rally) noiro@fab8-ext-rtr-10-30-120-119:~/rally/local/lib/python2.7/site-packages/rally/noirotest_framework$ cat create_resources.py
from rally.plugins.openstack import scenario
from rally.noirotest_framework import gbputils
from rally.noirotest_framework.osutils import TestError

class CreateResources(gbputils.GBPScenario, scenario.OpenStackScenario):

    def create_gbp_policy_rule_set_east_west(self, gbp1):

        policy_ruleset_ids = {}
        policy_rules = {}
        print("Create GBP policy action")
        self.create_gbp_policy_action(gbp1, "demo_act", **{"action_type": "allow", "shared": False})
        act_id = self.verify_gbp_policy_action(gbp1, "demo_act")
        print("Create GBP classifier and rule sets for ICMP")
        cls_icmp_id, rule_icmp_id = self.create_gbp_classifier_and_policy_rule(
            gbp1, act_id, "demo_class_icmp", "icmp", "bi", "demo_rule_icmp")
        prs_icmp_id = self.create_gbp_policy_ruleset(gbp1, "demo_ruleset_icmp", rule_ids=[rule_icmp_id])
        policy_ruleset_ids.update({"icmp_id": prs_icmp_id})
        policy_rules.update({"icmp_id": rule_icmp_id})

        print("Create GBP classifier and rule sets for TCP")
        cls_tcp_id, rule_tcp_id = self.create_gbp_classifier_and_policy_rule(
            gbp1, act_id, "demo_class_tcp", "tcp", "bi", "demo_rule_tcp")
        prs_tcp_id = self.create_gbp_policy_ruleset(gbp1, "demo_ruleset_tcp", [rule_tcp_id])
        policy_ruleset_ids.update({"tcp_id": prs_tcp_id})
        policy_rules.update({"tcp_id": rule_tcp_id})

        print("Create GBP classifier and rule sets for UDP")
        cls_udp_id, rule_udp_id = self.create_gbp_classifier_and_policy_rule(
            gbp1, act_id, "demo_class_udp", "udp", "bi", "demo_rule_udp")
        prs_udp_id = self.create_gbp_policy_ruleset(gbp1, "demo_ruleset_udp", rule_ids=[rule_udp_id])
        policy_ruleset_ids.update({"udp_id": prs_udp_id})
        policy_rules.update({"udp_id": rule_udp_id})

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
