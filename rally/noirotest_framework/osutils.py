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
_log = logging.getLogger(__name__)


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

        role_id = self._clients.keystone("3").roles.list(name=role_name)[0].id
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

        limit = len(self._admin_clients.keystone("3").users.list())
        for i in range(0, limit):
            if self._admin_clients.keystone("3").users.list()[i].name == 'admin':
                admin_id = self._admin_clients.keystone("3").users.list()[i].id

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
        super(scenario.OpenStackScenario, self).__init__(context)

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

        self._init_profiler(context)

    @atomic.action_timer("nova.admin_boot_server")
    def _admin_boot_server(self, image, flavor,
                           auto_assign_nic=False, **kwargs):

        server_name = self.generate_random_name()

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

    @atomic.action_timer("neutron.admin_delete_port")
    def _admin_delete_port(self, port):

        self.admin_clients("neutron").delete_port(port["port"]["id"])

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
    def create_address_scope(self, name, ip_version, shared=False, **kwargs):
        """
		Create an Address Scope
		"""
        address_scope = {"name": name, "ip_version": ip_version, "shared": shared}
        for arg, val in kwargs.items():
            address_scope[arg] = val
        body = {"address_scope": address_scope}
        if shared:
            return self.admin_clients("neutron").create_address_scope(body)
        else:
            return self.clients("neutron").create_address_scope(body)

    @atomic.action_timer("neutron.delete_address_scope")
    def delete_address_scope(self, addscope_id):

        self.admin_clients("neutron").delete_address_scope(addscope_id)

    @atomic.action_timer("neutron.create_subnet_pool")
    def create_subnet_pool(self, name, add_scope, prefixes, def_prefixlen, shared=False, **kwargs):
        """
		Create an Address Scope
		"""
        subnet_pool = {"name": name, "address_scope_id": add_scope, "prefixes": [prefixes],
                       "default_prefixlen": def_prefixlen, "shared": shared}
        for arg, val in kwargs.items():
            subnet_pool[arg] = val
        body = {"subnetpool": subnet_pool}
        if shared:
            return self.admin_clients("neutron").create_subnetpool(body)
        else:
            return self.clients("neutron").create_subnetpool(body)

    @atomic.action_timer("neutron.delete_subnet_pool")
    def delete_subnet_pool(self, subpool_id):

        self.admin_clients("neutron").delete_subnetpool(subpool_id)

    def install_secgroup_rules(self, secgroup, default_route='0.0.0.0/0'):

        sec = self._show_security_group(secgroup)
        sec_id = sec.get("security_group").get("id")
        self._create_security_group_rule(sec_id, {"protocol": "icmp", "direction": "ingress", "prefix": default_route,
                                                  "dst_port": "-1:-1"})
        self._create_security_group_rule(sec_id, {"protocol": "tcp", "direction": "ingress", "prefix": default_route,
                                                  "dst_port": "22:22"})
        self._create_security_group_rule(sec_id, {"protocol": "tcp", "direction": "ingress", "prefix": default_route,
                                                  "dst_port": "80:80"})




class TestError(Exception):
    pass
