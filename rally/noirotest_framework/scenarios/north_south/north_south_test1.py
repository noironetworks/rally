from rally import consts
from rally.common import validation
from rally.plugins.openstack import scenario
from rally.noirotest_framework import create_resources
from rally.noirotest_framework import gbputils
from rally.noirotest_framework import osutils
from rally.plugins.openstack.scenarios.nova import utils as nova_utils
from rally.plugins.openstack.scenarios.neutron import utils as neutron_utils


@validation.add("required_services", services=[consts.Service.NOVA, consts.Service.NEUTRON])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(name="ScenarioPlugin.north_south_test1", context={"cleanup@openstack": ["nova", "neutron"]},
                    platform="openstack")
class NorthSouth(neutron_utils.NeutronScenario, gbputils.GBPScenario, osutils.OSScenario, nova_utils.NovaScenario,
                 scenario.OpenStackScenario, create_resources.CreateResources):

    def run(self, controller_ip, image, flavor):
        plugin_type = 'merged'
        gbp_ad = self.gbp_client(controller_ip, "admin", "noir0123", "admin")
        gbp, key_name, user, project = self.create_gbp_object_for_new_user(controller_ip, 'NSTEST', 'nstest',
                                                                           'noir0123', 'nstest')

        ext_net_list, ext_sub_list, vm_list = self.create_resources_for_north_south_tests(gbp_ad, gbp,
                                                                                          key_name, image, flavor)

        fip1 = self._attach_floating_ip(vm_list[0], ext_net_list[0])
        fip2 = self._attach_floating_ip(vm_list[1], ext_net_list[0])
        self.sleep_between(10, 15)

        ##################################################
        # add route in external router
        ########################################

        ##################################################
        # traffic verification from ext-router to fip
        #########################################
        self._dissociate_floating_ip(vm_list[0], fip1)
        self._dissociate_floating_ip(vm_list[1], fip2)
        self.sleep_between(10, 15)

        self._associate_floating_ip(vm_list[0], fip2)
        self._associate_floating_ip(vm_list[1], fip1)
        self.sleep_between(10, 15)
        self.cleanup_resources(gbp_ad, vm_list, ext_net_list, fip2, fip1, user, project)
