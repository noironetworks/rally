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
@scenario.configure(name="ScenarioPlugin.north_south_test5", context={"cleanup@openstack": ["nova", "neutron"]},
                    platform="openstack")
class NorthSouth(neutron_utils.NeutronScenario, gbputils.GBPScenario, osutils.OSScenario, nova_utils.NovaScenario,
                 scenario.OpenStackScenario, create_resources.CreateResources):

    def run(self, controller_ip, image, flavor):
        gbp_ad = self.gbp_client(controller_ip, "admin", "noir0123", "admin")
        gbp, key_name, user, project = self.create_gbp_object_for_new_user(controller_ip, 'NSTEST', 'nstest',
                                                                           'noir0123', 'nstest')

        ext_net_list, ext_sub_list, vm_list, l3p, defaultl3p, nat_pool, prs_icmp_tcp_id = self.create_resources_for_north_south_tests(gbp_ad,
            gbp, key_name, image, flavor, external_seg2=True)

        fip1 = self._attach_floating_ip(vm_list[0], ext_net_list[0])
        fip2 = self._attach_floating_ip(vm_list[1], ext_net_list[0])
        self.sleep_between(10, 15)

        ##################################################
        # add route in external router
        ########################################

        ##################################################
        # traffic verification from ext-router to fip
        #########################################
        self._delete_floating_ip(vm_list[0], fip1)
        self._delete_floating_ip(vm_list[1], fip2)

        ext_seg2 = self.create_gbp_external_segment(gbp_ad, "L3OUT2",
                                                    **{"subnet_id": ext_sub_list[2].id, "external_routes": [
                                                        {"destination": "0.0.0.0/0", "nexthop": None}],
                                                       "shared": True})
        self.update_gbp_l3policy(gbp, l3p, "uuid", **{"external_segments": ext_seg2})
        self.update_gbp_l3policy(gbp, defaultl3p, "uuid", **{"external_segments": ext_seg2})
        self.update_gbp_nat_pool(gbp, nat_pool, **{"external_segment_id": ext_seg2})

        ext_pol2 = self.create_gbp_external_policy(gbp, "L3OUT2_NET", **{"external_segments": [ext_seg2]})
        self.update_gbp_external_policy(gbp, ext_pol2, "uuid", [prs_icmp_tcp_id])

        fip3 = self._attach_floating_ip(vm_list[0], ext_net_list[1])
        fip4 = self._attach_floating_ip(vm_list[1], ext_net_list[1])
        self.sleep_between(10, 15)

        ##################################################
        # add route in external router
        ########################################

        ##################################################
        # traffic verification from ext-router to fip
        #########################################

        self.cleanup_resources(gbp_ad, vm_list, ext_net_list, fip2, fip1, user, project)



