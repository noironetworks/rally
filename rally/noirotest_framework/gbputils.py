from rally.common import cfg
from rally.task import atomic
from rally.common import logging
from keystoneauth1 import session
from keystoneauth1 import identity
from rally.plugins.openstack import scenario
from gbpclient.v2_0 import client as gbpclient

CONF = cfg.CONF
_log = logging.getLogger(__name__)


class GBPScenario(scenario.OpenStackScenario):

    def gbp_client(self, ostack_controller, username,
                   password, tenant):

        cred = {'username': username, 'password': password, 'tenant_name': tenant,
                'auth_url': "http://%s:5000/v3/" % ostack_controller}
        auth = identity.Password(auth_url=cred['auth_url'],
                                 username=username,
                                 password=password,
                                 project_name=tenant,
                                 project_domain_name='Default',
                                 user_domain_name='Default')
        sess = session.Session(auth=auth)

        self.client = gbpclient.Client(session=sess)
        return self.client

    @atomic.action_timer("gbp.create_policy_action")
    def create_gbp_policy_action(self, gbp_client, name, **kwargs):
        """
		Create a GBP Policy Action
		Supported  keyword based attributes and their values:
		'action_type'= 'allow','redirect'
		'action_value'= uuid string
		'shared'= 'True', 'False'
		'description'= any string
		"""
        policy_action = {"name": name}
        try:
            for arg, val in kwargs.items():
                policy_action[arg] = val
            body = {"policy_action": policy_action}
            gbp_client.create_policy_action(body)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Create of Policy Action= %s, failed" % name)
            return 0

    @atomic.action_timer("gbp.verify_policy_action")
    def verify_gbp_policy_action(self, gbp_client, name):
        """
		Verify the GBP Policy Action by passing its name
		"""
        for action in gbp_client.list_policy_actions()['policy_actions']:
            if action['name'].encode('ascii') == name:
                return action['id'].encode('ascii')
        _log.error("Policy Action NOT Found")
        return 0

    @atomic.action_timer("gbp.update_policy_action")
    def update_gbp_policy_action(self, gbp_client, name_uuid,
                                 property_type='name', **kwargs):
        """
		 Update a GBP Policy Action
		 Supported  keyword based attributes and their values:
		 'action_type'= 'allow','redirect'
		 'action_value'= uuid string
		 'shared'= 'True', 'False'
		 'description'= any string
		 """
        if property_type == 'uuid':
            action_id = name_uuid
        else:
            action_id = self.verify_gbp_policy_action(gbp_client, name_uuid)
        policy_action = {}
        try:
            for arg, val in kwargs.items():
                policy_action[arg] = val
            body = {"policy_action": policy_action}
            gbp_client.update_policy_action(action_id, body)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Update of Policy Action= %s, failed" % name_uuid)
            return 0

    @atomic.action_timer("gbp.list_policy_action")
    def get_gbp_policy_action_list(self, gbp_client, getdict=False):
        """
		Fetch a List of GBP Policy Actions
		getdict: 'True', will return a dictionary comprising 'name' & 'uuid'
		"""
        try:
            if getdict:
                name_uuid = {}
                for action in gbp_client.list_policy_actions()['policy_actions']:
                    name_uuid[action['name'].encode('ascii')] = action['id'].encode('ascii')
            else:  # Return list of ids
                pa_list = [item['id'] for item in gbp_client.list_policy_actions()['policy_actions']]
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Fetching Policy Action List, failed")
            return 0
        if getdict:
            return name_uuid
        else:
            return pa_list

    @atomic.action_timer("gbp.show_policy_action")
    def get_gbp_policy_action_show(self, gbp_client, uuid):
        """
		Fetch the details of a given GBP Policy Action
		"""
        try:
            pa = gbp_client.show_policy_action(uuid)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Fetching a given Policy Action=%s, failed" % uuid)
            return 0
        return pa

    @atomic.action_timer("gbp.delete_policy_action")
    def delete_gbp_policy_action(self, gbp_client, name_uuid, property_type='name'):
        """
		 Delete a GBP Policy Action
		 property_type='name' or 'uuid'
		 If property_type=='name', pass 'name_string' for name_uuid,
		 else pass 'uuid_string' for name_uuid param
		 """
        try:
            if property_type == 'name':
                action_uuid = self.verify_gbp_policy_action(gbp_client, name_uuid)
                gbp_client.delete_policy_action(action_uuid)
            else:
                gbp_client.delete_policy_action(name_uuid)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Deleting Policy Action = %s, failed" % name_uuid)
            return 0

    @atomic.action_timer("gbp.create_policy_classifier")
    def create_gbp_policy_classifier(self, gbp_client, name, **kwargs):
        """
		Create GBP Policy Classifier
		Supported  keyword based attributes and their values:
		'direction'= 'in','bi','out'
		'protocol'= 'tcp','udp','icmp'
		'port_range'= 'x:y', where x<=y, 66:67 or 66:66
		'shared'= 'True', 'False'
		'description'= any string
		"""
        policy_classifier = {"name": name}
        try:
            for arg, val in kwargs.items():
                policy_classifier[arg] = val
            body = {"policy_classifier": policy_classifier}
            gbp_client.create_policy_classifier(body)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Create of Policy Classifier= %s, failed" % name)
            return 0

    @atomic.action_timer("gbp.update_policy_classifier")
    def update_gbp_policy_classifier(self, gbp_client, name_uuid,
                                     property_type='name', **kwargs):
        """
		 Update GBP Policy Classifier editable attributes
		 Supported  keyword based attributes and their values:
		 'direction'= 'in','bi','out'
		 'protocol'= 'tcp','udp','icmp'
		 'port_range'= 'x:y', where x<=y, 66:67 or 66:66
		 'shared'= 'True', 'False'
		 'description'= any string
		 """
        if property_type == 'uuid':
            classifier_id = name_uuid
        else:
            classifier_id = self.verify_gbp_policy_classifier(gbp_client, name_uuid)
        policy_classifier = {}
        try:
            for arg, val in kwargs.items():
                policy_classifier[arg] = val
            body = {"policy_classifier": policy_classifier}
            gbp_client.update_policy_classifier(classifier_id, body)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Update of Policy Classifier= %s, failed" % name_uuid)
            return 0

    @atomic.action_timer("gbp.list_policy_classifier")
    def get_gbp_policy_classifier_list(self, gbp_client, getdict=False):
        """
		Fetch a List of GBP Policy Classifiers
		getdict: 'True', will return a dictionary comprising 'name' & 'uuid'
		"""
        try:
            if getdict:
                name_uuid = {}
                for classifier in gbp_client.list_policy_classifiers()['policy_classifiers']:
                    name_uuid[classifier['name'].encode('ascii')] = classifier['id'].encode('ascii')
            else:
                pc_list = [item['id'] for item in gbp_client.list_policy_classifiers()['policy_classifiers']]
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Fetching Policy Classifier List, failed")
            return 0
        if getdict:
            return name_uuid
        else:
            return pc_list

    @atomic.action_timer("gbp.delete_policy_classifier")
    def delete_gbp_policy_classifier(self, gbp_client, name_uuid, property_type='name'):
        """
		 Delete a GBP Policy Classifier
		 property_type='name' or 'uuid'
		 If property_type=='name', pass 'name_string' for name_uuid,
		 else pass 'uuid_string' for name_uuid param
		 """
        try:
            if property_type == 'name':
                class_uuid = self.verify_gbp_policy_classifier(gbp_client, name_uuid)
                gbp_client.delete_policy_classifier(class_uuid)
            else:
                gbp_client.delete_policy_classifier(name_uuid)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Deleting Policy Classifier = %s, failed" % name_uuid)
            return 0

    @atomic.action_timer("gbp.verify_policy_classifier")
    def verify_gbp_policy_classifier(self, gbp_client, name):
        """
		Verify the GBP Policy Classifier by passing its name and fetch its UUID
		"""
        for classifier in gbp_client.list_policy_classifiers()['policy_classifiers']:
            if classifier['name'].encode('ascii') == name:
                return classifier['id'].encode('ascii')
        _log.error("Policy Classifier NOT Found")
        return 0

    @atomic.action_timer("gbp.create_policy_rule")
    def create_gbp_policy_rule(self, gbp_client, name, classifier, action,
                               property_type='name', **kwargs):
        """
		Create a GBP Policy Rule
		classifier/action: Pass name-string or uuid-string
		depending on property_type
		property_type: 'uuid' or 'name'(default)
		Supported  keyword based attributes and their values:
		'shared'= 'True', 'False'
		'description'= any string
		"""
        if property_type == 'name':
            classifier_id = self.verify_gbp_policy_classifier(gbp_client, classifier)
            action_id = self.verify_gbp_policy_action(gbp_client, action)
        else:
            classifier_id = classifier
            action_id = action
        policy_rule = {"policy_actions": [action_id],
                       "policy_classifier_id": classifier_id,
                       "name": name
                       }
        try:
            for arg, val in kwargs.items():
                policy_rule[arg] = val
            body = {"policy_rule": policy_rule}
            gbp_client.create_policy_rule(body)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Creating Policy Rule = %s, failed" % name)
            return 0

    @atomic.action_timer("gbp.update_policy_rule")
    def update_gbp_policy_rule(self, gbp_client, name_uuid, property_type='name', **kwargs):
        """
		 Update GBP Policy Rule editable attributes
		 Supported  keyword based attributes and their values:
		 'policy_classifer'= uuid of policy_classifier
		 'policy_actions' = uuid of policy_action
		 'shared'= 'True', 'False'
		 'description'= any string
		 """
        if property_type == 'uuid':
            rule_id = name_uuid
        else:
            rule_id = self.verify_gbp_policy_rule(gbp_client, name_uuid)
        policy_rule = {}
        try:
            for arg, val in kwargs.items():
                policy_rule[arg] = val
            body = {"policy_rule": policy_rule}
            gbp_client.update_policy_rule(rule_id, body)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Update of Policy Rule= %s, failed" % name_uuid)
            return 0

    @atomic.action_timer("gbp.verify_policy_rule")
    def verify_gbp_policy_rule(self, gbp_client, name):
        """
		Verify the GBP Policy Rule by passing its name and fetch its UUID
		"""
        for rule in gbp_client.list_policy_rules()['policy_rules']:
            if rule['name'].encode('ascii') == name:
                return rule['id'].encode('ascii')
        _log.error("Policy Rule NOT Found")
        return 0

    @atomic.action_timer("gbp.list_policy_rule")
    def get_gbp_policy_rule_list(self, gbp_client, getdict=False):
        """
		Fetch a List of GBP Policy Rules
		getdict: 'True', will return a dictionary comprising 'name' & 'uuid'
		"""
        try:
            if getdict:
                name_uuid = {}
                for rule in gbp_client.list_policy_rules()['policy_rules']:
                    name_uuid[rule['name'].encode('ascii')] = rule['id'].encode('ascii')
            else:
                rules_list = [item['id'] for item in gbp_client.list_policy_rules()['policy_rules']]
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Fetching Policy Rule List, failed")
            return 0
        if getdict:
            return name_uuid
        else:
            return rules_list

    @atomic.action_timer("gbp.delete_policy_rule")
    def delete_gbp_policy_rule(self, gbp_client, name_uuid, property_type='name'):
        """
		 Delete a GBP Policy Rule
		 property_type='name' or 'uuid'
		 If property_type=='name', pass 'name_string' for name_uuid,
		 else pass 'uuid_string' for name_uuid param
		 """
        try:
            if property_type == 'name':
                rule_uuid = self.verify_gbp_policy_rule(gbp_client, name_uuid)
                gbp_client.delete_policy_rule(rule_uuid)
            else:
                gbp_client.delete_policy_rule(name_uuid)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Deleting Policy Rule = %s, failed" % name_uuid)
            return 0

    @atomic.action_timer("gbp.create_policy_rule_set")
    def create_gbp_policy_rule_set(self, gbp_client, name, rule_list=[],
                                   property_type='name', **kwargs):
        """
		Create a GBP Policy RuleSet
		rule_list: List of policy_rules,pass list of rule_names or rule_uuid strings
			   depending on the property_type(defaulted to 'name')
		Supported  keyword based attributes and their values:
		'shared' = False,True
		'description' = any string
		"""
        try:
            if property_type == 'name':
                temp = rule_list
                rule_list = []
                for rule in temp:
                    rule_uuid = self.verify_gbp_policy_rule(gbp_client, rule)
                    rule_list.append(rule_uuid)
            policy_rule_set = {"name": name, "policy_rules": rule_list}
            for arg, val in kwargs.items():
                policy_rule_set[arg] = val
            body = {"policy_rule_set": policy_rule_set}
            gbp_client.create_policy_rule_set(body)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Creating Policy RuleSet = %s, failed" % name)
            return 0

    @atomic.action_timer("gbp.verify_policy_rule_set")
    def verify_gbp_policy_rule_set(self, gbp_client, name):
        """
		Verify the GBP Policy RuleSet by passing its name and fetch its UUID
		"""
        for ruleset in gbp_client.list_policy_rule_sets()['policy_rule_sets']:
            if ruleset['name'].encode('ascii') == name:
                return ruleset['id'].encode('ascii')
        _log.error("Policy RuleSet NOT Found")
        return 0

    @atomic.action_timer("gbp.update_policy_rule_set")
    def update_gbp_policy_rule_set(self, gbp_client, name_uuid,
                                   property_type='name', **kwargs):
        """
		 Update GBP Policy Rule editable attributes
		 Supported  keyword based attributes and their values/type:
		 'policy_rules'= [list of policy-rule uuid]
		 'shared'= 'True', 'False'
		 'description'= any string
		 """
        if property_type == 'uuid':
            ruleset_id = name_uuid
        else:
            ruleset_id = self.verify_gbp_policy_rule_set(gbp_client, name_uuid)
        policy_rule_set = {}
        try:
            for arg, val in kwargs.items():
                policy_rule_set[arg] = val
            body = {"policy_rule_set": policy_rule_set}
            gbp_client.update_policy_rule_set(ruleset_id, body)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Update of Policy RuleSet= %s, failed" % name_uuid)
            return 0

    @atomic.action_timer("gbp.delete_policy_rule_set")
    def delete_gbp_policy_rule_set(self, gbp_client, name_uuid, property_type='name'):
        """
		 Delete a GBP Policy RuleSet
		 property_type='name' or 'uuid'
		 If property_type=='name', pass 'name_string' for name_uuid,
		 else pass 'uuid_string' for name_uuid param
		 """
        try:
            if property_type == 'name':
                ruleset_uuid = self.verify_gbp_policy_rule_set(gbp_client, name_uuid)
                gbp_client.delete_policy_rule_set(ruleset_uuid)
            else:
                gbp_client.delete_policy_rule_set(name_uuid)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Deleting Policy RuleSet = %s, failed" % name_uuid)
            return 0

    @atomic.action_timer("gbp.list_policy_rule_set")
    def get_gbp_policy_rule_set_list(self, gbp_client, getdict=False):
        """
		Fetch a List of GBP Policy RuleSet
		getdict: 'True', will return a dictionary comprising 'name' & 'uuid'
		"""
        try:
            if getdict:
                name_uuid = {}
                for ruleset in gbp_client.list_policy_rule_sets()['policy_rule_sets']:
                    name_uuid[ruleset['name'].encode('ascii')] = ruleset['id'].encode('ascii')
            else:
                rulesets_list = [item['id'] for item in gbp_client.list_policy_rule_sets()['policy_rule_sets']]
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Fetching Policy RuleSet List, failed")
            return 0
        if getdict:
            return name_uuid
        else:
            return rulesets_list

    @atomic.action_timer("gbp.create_policy_target_group")
    def create_gbp_policy_target_group(self, gbp_client, name, **kwargs):
        """
		Create a GBP Policy Target Group
		Supported  keyword based attributes and their values/types:
		'l2_policy_id' = l2policy_uuid
		'network_service_policy_id' = nsp_uuid
		'consumed_policy_rule_sets' = [list of policy_rule_set_uuid]
		'provided_policy_rule_sets' = [list policy_rule_set_uuid]
		'nextwork_service_policy' = name_uuid_network_service_policy
		'shared' = False,True
		'description' = any string
		"""
        try:
            policy_target_group = {"name": name}
            for arg, val in kwargs.items():
                policy_target_group[arg] = val
            body = {"policy_target_group": policy_target_group}
            ptg_uuid = gbp_client.create_policy_target_group(body)['policy_target_group']['id'].encode('ascii')

        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Creating Policy Target Group = %s, failed" % name)
            return 0
        return ptg_uuid

    @atomic.action_timer("gbp.verify_policy_target_group")
    def verify_gbp_policy_target_group(self, gbp_client, name):
        """
		Verify the GBP Policy Target Group by passing its name and fetch its UUID
		"""
        for ptg in gbp_client.list_policy_target_groups()['policy_target_groups']:
            if ptg['name'].encode('ascii') == name:
                return ptg['id'].encode('ascii')
        _log.error("Policy Target Group NOT Found")
        return 0

    @atomic.action_timer("gbp.update_policy_target_group")
    def update_gbp_policy_target_group(self, gbp_client, name_uuid,
                                       property_type='name',
                                       consumed_policy_rulesets='',
                                       provided_policy_rulesets='',
                                       shared=False,
                                       network_service_policy='', **kwargs):
        """
		Update the Policy Target Group
		Provide uniform property_type('name' or 'uuid') across objects
		Pass policy_rulesets as []
		"""
        try:
            consumed_dict = {}
            provided_dict = {}
            if property_type == 'name':
                group_id = self.verify_gbp_policy_target_group(gbp_client, name_uuid)
                if consumed_policy_rulesets:
                    for ruleset in consumed_policy_rulesets:
                        id = self.verify_gbp_policy_rule_set(gbp_client, ruleset)
                        consumed_dict[id] = "scope"
                if provided_policy_rulesets:
                    for ruleset in provided_policy_rulesets:
                        id = self.verify_gbp_policy_rule_set(gbp_client, ruleset)
                        provided_dict[id] = "scope"
            else:
                group_id = name_uuid
                if consumed_policy_rulesets:
                    for ruleset in consumed_policy_rulesets:
                        consumed_dict[ruleset] = "scope"
                if provided_policy_rulesets:
                    for ruleset in provided_policy_rulesets:
                        provided_dict[ruleset] = "scope"
            body = {"policy_target_group": {"shared": shared}}
            if kwargs.items:
                policy_target_group = {}
                for arg, val in kwargs.items():
                    policy_target_group[arg] = val
                policy_target_group[shared] = shared
                body = {"policy_target_group": policy_target_group}
            if consumed_policy_rulesets != '' and consumed_policy_rulesets is not None:
                if provided_policy_rulesets != '' and provided_policy_rulesets is not None:
                    body = {"policy_target_group": {
                        "provided_policy_rule_sets": provided_dict,
                        "consumed_policy_rule_sets": consumed_dict
                    }
                    }
                if provided_policy_rulesets == '':
                    body = {"policy_target_group": {
                        "consumed_policy_rule_sets": consumed_dict
                    }
                    }
                if provided_policy_rulesets is None:
                    body = {"policy_target_group": {
                        "consumed_policy_rule_sets": consumed_dict,
                        "provided_policy_rule_sets": None
                    }
                    }
                if network_service_policy != '' and network_service_policy is not None:
                    body["policy_target_group"]["network_service_policy_id"] = network_service_policy
            elif provided_policy_rulesets != '' and provided_policy_rulesets is not None:
                if consumed_policy_rulesets == '':
                    body = {"policy_target_group": {
                        "provided_policy_rule_sets": provided_dict
                    }
                    }
                if consumed_policy_rulesets is None:
                    body = {"policy_target_group": {
                        "provided_policy_rule_sets": provided_dict,
                        "consumed_policy_rule_sets": None
                    }
                    }

                if network_service_policy != '' and network_service_policy is not None:
                    body["policy_target_group"]["network_service_policy_id"] = network_service_policy
            elif provided_policy_rulesets is None and consumed_policy_rulesets is None:
                body = {"policy_target_group": {
                    "provided_policy_rule_sets": {},
                    "consumed_policy_rule_sets": {}
                }
                }
                if network_service_policy != '' and network_service_policy is not None:
                    body["policy_target_group"]["network_service_policy_id"] = network_service_policy
            elif provided_policy_rulesets == '' and consumed_policy_rulesets == '':
                if network_service_policy is None:
                    body["policy_target_group"]["network_service_policy_id"] = None
                if network_service_policy != '' and network_service_policy is not None:
                    body["policy_target_group"]["network_service_policy_id"] = network_service_policy
            else:
                print('Do nothing')
                return 1
            gbp_client.update_policy_target_group(group_id, body)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Updating Policy Target Group = %s, failed" % name_uuid)
            return 0

    @atomic.action_timer("gbp.delete_policy_target_group")
    def delete_gbp_policy_target_group(self, gbp_client, name_uuid, property_type='name'):
        """
		 Delete a GBP Policy Group
		 property_type='name' or 'uuid'
		 If property_type=='name', pass 'name_string' for name_uuid,
		 else pass 'uuid_string' for name_uuid param
		 """
        try:
            if property_type == 'name':
                ptg_uuid = self.verify_gbp_policy_target_group(gbp_client, name_uuid)
                gbp_client.delete_policy_target_group(ptg_uuid)
            else:
                gbp_client.delete_policy_target_group(name_uuid)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Deleting Policy Target Group = %s, failed" % name_uuid)
            return 0

    @atomic.action_timer("gbp.list_policy_target_group")
    def get_gbp_policy_target_group_list(self, gbp_client, getdict=False):
        """
		Fetch a List of GBP Policy Target Group
		getdict: 'True', will return a dictionary comprising 'name' & 'uuid'
		"""
        try:
            if getdict:
                name_uuid = {}
                for ptg in gbp_client.list_policy_target_groups()['policy_target_groups']:
                    name_uuid[ptg['name'].encode('ascii')] = ptg['id'].encode('ascii')
            else:
                ptgs_list = [item['id'] for item in gbp_client.list_policy_target_groups()['policy_target_groups']]
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Fetching Policy Target Group List, failed")
            return 0
        if getdict:
            return name_uuid
        else:
            return ptgs_list

    @atomic.action_timer("gbp.create_policy_target")
    def create_gbp_policy_target(self, gbp_client, name, ptg_name, pt_count=1, ptg_property='name'):
        """
		Create a Policy Target for a given PTG
		'pt_count':: number of PTs to be created for a given PTG
		'ptg_property':: ptg passed can be 'name' or 'uuid'
		"""
        try:
            if ptg_property == 'name':
                ptg_id = self.verify_gbp_policy_target_group(gbp_client, ptg_name)
            else:
                ptg_id = ptg_name
            for i in range(pt_count):
                body = {"policy_target": {
                    "policy_target_group_id": ptg_id,
                    "name": name
                }
                }
                post_result = gbp_client.create_policy_target(body)['policy_target']
                pt_uuid = post_result['id'].encode('ascii')
                neutron_port_id = post_result['port_id'].encode('ascii')
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Creating PT = %s, failed" % name)
            return 0
        return pt_uuid, neutron_port_id

    @atomic.action_timer("gbp.verify_policy_target")
    def verify_gbp_policy_target(self, gbp_client, name):
        """
		Verify the GBP Policy Target by passing its name
		Returns PT and its corresponding Neutron Port UUIDs
		"""
        for pt in gbp_client.list_policy_targets()['policy_targets']:
            if pt['name'].encode('ascii') == name:
                return pt['id'].encode('ascii'), pt['port_id'].encode('ascii')
        _log.error("Policy Target NOT Found")
        return 0

    @atomic.action_timer("gbp.update_policy_target")
    def update_gbp_policy_target(self, gbp_client, name_uuid,
                                 property_type='name', **kwargs):
        """
		 Update GBP Policy Target
		 """
        if property_type == 'uuid':
            pt_id = name_uuid
        else:
            pt_id = self.verify_gbp_policy_target(gbp_client, name_uuid)
        policy_target = {}
        try:
            for arg, val in kwargs.items():
                policy_target[arg] = val
            body = {"policy_target": policy_target}
            gbp_client.update_policy_target(pt_id[0], body)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Update of Policy Target= %s, failed" % name_uuid)
            return 0

    @atomic.action_timer("gbp.list_policy_target")
    def get_gbp_policy_target_list(self, gbp_client):
        """
		Fetches a list of Policy Targets
		Returns a dict of Policy Targets UUIDs
		and their corresponding Neutron Port UUIDs
		"""
        pt_nic_id = {}
        pt_list = gbp_client.list_policy_targets()['policy_targets']
        if len(pt_list):
            for pt in pt_list:
                try:
                    pt_nic_id[pt['id']] = pt['port_id']
                except Exception as e:
                    print(Exception)
                    _log.error("\nException Error: %s\n" % e)
                    continue
        return pt_nic_id

    @atomic.action_timer("gbp.delete_policy_target")
    def delete_gbp_policy_target(self, gbp_client, name_uuid, property_type='name'):
        """
		 Delete a GBP Policy Target
		 property_type='name' or 'uuid'
		 If property_type=='name', pass 'name_string' for name_uuid,
		 else pass 'uuid_string' for name_uuid param
		 """
        try:
            if property_type == 'name':
                pt_uuid = self.verify_gbp_policy_target(gbp_client, name_uuid)
                gbp_client.delete_policy_target(pt_uuid[0])
            else:
                gbp_client.delete_policy_target(name_uuid)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Deleting Policy Target = %s, failed" % name_uuid)
            return 0

    @atomic.action_timer("gbp.create_l3_policy")
    def create_gbp_l3policy(self, gbp_client, name, **kwargs):
        """
		Create a GBP L3Policy
		Supported  keyword based attributes and their values/type:
		'ip_pool' = string (eg:'1.2.3.0/24')
		'subnet_prefix_length' = integer
		'external_segments': {}
		'shared': True, False
		'description': string
		"""
        try:
            l3policy = {"name": name}
            for arg, val in kwargs.items():
                if arg == 'external_segments':
                    val = {val: []}
                l3policy[arg] = val
            body = {"l3_policy": l3policy}
            l3p_uuid = gbp_client.create_l3_policy(body)['l3_policy']['id'].encode('ascii')
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Creating L3Policy = %s, failed" % name)
            return 0
        return l3p_uuid

    @atomic.action_timer("gbp.verify_l3_policy")
    def verify_gbp_l3policy(self, gbp_client, name):
        """
		Verify the GBP L3Policy by passing its name and fetch its UUID
		"""
        for l3p in gbp_client.list_l3_policies()['l3_policies']:
            if l3p['name'].encode('ascii') == name:
                return l3p['id'].encode('ascii')
        _log.error("L3Policy NOT Found")
        return 0

    @atomic.action_timer("gbp.delete_l3_policy")
    def delete_gbp_l3policy(self, gbp_client, name_uuid, property_type='name'):
        """
		 Delete a GBP L3Policy
		 property_type='name' or 'uuid'
		 If property_type=='name', pass 'name_string' for name_uuid,
		 else pass 'uuid_string' for name_uuid param
		 """
        try:
            if property_type == 'name':
                l3p_uuid = self.verify_gbp_l3policy(gbp_client, name_uuid)
                gbp_client.delete_l3_policy(l3p_uuid)
            else:
                gbp_client.delete_l3_policy(name_uuid)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Deleting L3Policy = %s, failed" % name_uuid)
            return 0

    @atomic.action_timer("gbp.update_l3_policy")
    def update_gbp_l3policy(self, gbp_client, name_uuid, property_type='name', **kwargs):
        """
		 Update GBP L3Policy editable attributes
		 Supported keyword based attributes and their values/type:
		 'subnet_prefix_length' = integer'
		 'shared'= 'True', 'False'
		 'description'= any string
		 'external_segments'= UUID of the external segment
		 """
        if property_type == 'uuid':
            l3p_id = name_uuid
        else:
            l3p_id = self.verify_gbp_l3policy(gbp_client, name_uuid)
        l3p = {}
        try:
            for arg, val in kwargs.items():
                if arg == 'external_segments':
                    val = {val: []}
                l3p[arg] = val
            body = {"l3_policy": l3p}
            gbp_client.update_l3_policy(l3p_id, body)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Update of L3Policy = %s, failed" % name_uuid)
            return 0

    @atomic.action_timer("gbp.list_l3_policy")
    def get_gbp_l3policy_list(self, gbp_client, getdict=False):
        """
		Fetch a List of GBP L3Policy
		getdict: 'True', will return a dictionary comprising 'name' & 'uuid'
		"""
        try:
            if getdict:
                name_uuid = {}
                for l3p in gbp_client.list_l3_policies()['l3_policies']:
                    name_uuid[l3p['name'].encode('ascii')] = l3p['id'].encode('ascii')
            else:
                l3p_list = [item['id'] for item in gbp_client.list_l3_policies()['l3_policies']]
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Fetching L3Policy List, failed")
            return 0
        if getdict:
            return name_uuid
        else:
            return l3p_list

    @atomic.action_timer("gbp.create_l2_policy")
    def create_gbp_l2policy(self, gbp_client, name, getl3p=False, autoptg=False, **kwargs):
        """
		Create a GBP L2Policy
		Supported  keyword based attributes and their values/type:
		'l3_policy_id' = string (uuid/name)
		'subnet_prefix_length' = integer
		'shared': True, False
		'description': string
		"""
        try:
            l2policy = {"name": name}
            for arg, val in kwargs.items():
                l2policy[arg] = val
            body = {"l2_policy": l2policy}
            output = gbp_client.create_l2_policy(body)
            l2p_uuid = output['l2_policy']['id'].encode('ascii')
            if getl3p:
                l3p_uuid = output['l2_policy']['l3_policy_id'].encode('ascii')
            if autoptg:
                autoptg_uuid = output['l2_policy']['policy_target_groups'][0]
            neutron_ntk = output['l2_policy']['network_id'].encode('ascii')
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Creating L2Policy = %s, failed" % name)
            return 0
        if getl3p and autoptg:
            # Returning neutron network also
            return l2p_uuid, l3p_uuid, autoptg_uuid, neutron_ntk
        elif getl3p:
            return l2p_uuid, l3p_uuid
        elif autoptg:
            return l2p_uuid, autoptg_uuid, neutron_ntk
        else:
            return l2p_uuid

    @atomic.action_timer("gbp.verify_l2_policy")
    def verify_gbp_l2policy(self, gbp_client, name):
        """
		Verify the GBP L2Policy by passing its name and fetch its UUID
		"""
        try:
            for l2p in gbp_client.list_l2_policies()['l2_policies']:
                if l2p['name'].encode('ascii') == name:
                    return l2p['id'].encode('ascii')
            _log.error("L2Policy NOT Found")
            return 0
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Verifying L2Policy = %s, failed" % name)
            return 0

    @atomic.action_timer("gbp.update_l2_policy")
    def update_gbp_l2policy(self, gbp_client, name_uuid, property_type='name', **kwargs):
        """
		 Update GBP L2Policy editable attributes
		 Supported keyword based attributes and their values/type:
		 'l3_policy_id' = string (uuid/name)
		 'subnet_prefix_length' = integer'
		 'shared'= 'True', 'False'
		 'description'= any string
		 """
        if property_type == 'uuid':
            l2p_id = name_uuid
        else:
            l2p_id = self.verify_gbp_l2policy(gbp_client, name_uuid)
        l2p = {}
        try:
            for arg, val in kwargs.items():
                l2p[arg] = val
            body = {"l2_policy": l2p}
            gbp_client.update_l2_policy(l2p_id, body)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Update of L2Policy = %s, failed" % name_uuid)
            return 0

    @atomic.action_timer("gbp.delete_l2_policy")
    def delete_gbp_l2policy(self, gbp_client, name_uuid, property_type='name'):
        """
		 Delete a GBP L2Policy
		 property_type='name' or 'uuid'
		 If property_type=='name', pass 'name_string' for name_uuid,
		 else pass 'uuid_string' for name_uuid param
		 """
        try:
            if property_type == 'name':
                l2p_uuid = self.verify_gbp_l2policy(gbp_client, name_uuid)
                gbp_client.delete_l2_policy(l2p_uuid)
            else:
                gbp_client.delete_l2_policy(name_uuid)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Deleting L2Policy = %s, failed" % name_uuid)
            return 0

    @atomic.action_timer("gbp.list_l2_policy")
    def get_gbp_l2policy_list(self, gbp_client, getdict=False):
        """
		Fetch a List of GBP L2Policy
		getdict: 'True', will return a dictionary comprising 'name' & 'uuid'
		"""
        try:
            if getdict:
                name_uuid = {}
                for l2p in gbp_client.list_l2_policies()['l2_policies']:
                    name_uuid[l2p['name'].encode('ascii')] = l2p['id'].encode('ascii')
            else:
                l2p_list = [item['id'] for item in gbp_client.list_l2_policies()['l2_policies']]
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Fetching L2Policy List, failed")
            return 0
        if getdict:
            return name_uuid
        else:
            return l2p_list

    @atomic.action_timer("gbp.create_external_segment")
    def create_gbp_external_segment(self, gbp_client, name, **kwargs):
        """
		Create an External Segment
		Return Ext_Seg_uuid
		Supported  keyword based attributes and their values/type:
		'cidr' = string
		'external_policies'= [](list of external-policies)
		'external_routes' = [{'destination'=<>,'nexthop'=<>}](Pass list of dictionaries for each dest/nexthop pair)
		'nexthop' = string('address should be part of the cidr')
		'shared': True, False
		'description': string
		"""
        try:
            external_segment = {"name": name}
            for arg, val in kwargs.items():
                if arg == 'external_policies' or arg == 'external_routes':
                    if not isinstance(val, list):
                        raise TypeError
                external_segment[arg] = val
            body = {"external_segment": external_segment}
            ext_seg_uuid = gbp_client.create_external_segment(body)['external_segment']['id'].encode('ascii')
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Creating External Segment = %s, failed" % name)
            return 0
        return ext_seg_uuid

    @atomic.action_timer("gbp.delete_external_segment")
    def delete_gbp_external_segment(self, gbp_client, uuid):
        """
		 Delete a GBP External Segment
		 """
        try:
            gbp_client.delete_external_segment(uuid)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Deleting External Segment = %s, failed" % uuid)
            return 0

    @atomic.action_timer("gbp.update_external_segment")
    def update_gbp_external_segment(self, gbp_client, uuid, **kwargs):
        """
		Update an External Segment
		Supported  keyword based attributes and their values/type:
		'cidr' = string
		'external_policies'= [](list of external-policies)
		'external_routes' = [{'destination':<>,'nexthop':<>}](Pass list of dictionaries for each dest/nexthop pair)
		'nexthop' = string('address should be part of the cidr')
		'shared': True, False
		'description': string
		"""
        external_segment = {}
        try:
            for arg, val in kwargs.items():
                external_segment[arg] = val
            body = {"external_segment": external_segment}
            gbp_client.update_external_segment(uuid, body)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Update of External Segment = %s, failed" % uuid)
            return 0

    @atomic.action_timer("gbp.list_external_segment")
    def get_gbp_external_segment_list(self, gbp_client, getdict=False):
        """
		Fetch a List of GBP External Segments
		getdict: 'True', will return a dictionary comprising 'name' & 'uuid'
		"""
        try:
            if getdict:
                name_uuid = {}
                for extseg in gbp_client.list_external_segments()['external_segments']:
                    name_uuid[extseg['name'].encode('ascii')] = {}
                    name_uuid[extseg['name']]['id'] = extseg['id'].encode('ascii')
                    name_uuid[extseg['name']]['shared'] = extseg['shared']
                    name_uuid[extseg['name']]['l3_policies'] = extseg['l3_policies']
                    name_uuid[extseg['name']]['external_policies'] = extseg['external_policies']
            else:  # Return list of ids
                extseg_list = [item['id'] for item in gbp_client.list_external_segments()['external_segments']]
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Fetching External Segment List, failed")
            return 0
        if getdict:
            return name_uuid
        else:
            return extseg_list

    @atomic.action_timer("gbp.create_nat_pool")
    def create_gbp_nat_pool(self, gbp_client, name, **kwargs):
        """
		Create a NAT Pool
		Supported keywords based attributes and their values/type:
		'ip_pool' = string(must be exact or subnet of cidr)
		'external_segment_id' = string(name/uuid)
		"""
        nat_pool = {'name': name}
        try:
            for arg, val in kwargs.items():
                nat_pool[arg] = val
            body = {"nat_pool": nat_pool}
            nat_pool_uuid = gbp_client.create_nat_pool(body)['nat_pool']['id'].encode('ascii')
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            return 0
        return nat_pool_uuid

    @atomic.action_timer("gbp.delete_nat_pool")
    def delete_gbp_nat_pool(self, gbp_client, uuid):
        """
		 Delete a GBP NAT Pool
		 """
        try:
            gbp_client.delete_nat_pool(uuid)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Deleting NAT Pool %s, failed" % uuid)
            return 0

    @atomic.action_timer("gbp.list_nat_pool")
    def get_gbp_nat_pool_list(self, gbp_client, getdict=False):
        """
		Fetch a List of GBP NAT Pools
		getdict: 'True', will return a dictionary comprising 'name' & 'uuid'
		"""
        try:
            if getdict:
                name_uuid = {}
                for natpool in gbp_client.list_nat_pools()['nat_pools']:
                    name_uuid[natpool['name'].encode('ascii')] = natpool['id'].encode('ascii')
            else:  # Return list of ids
                natpool_list = [item['id'] for item in gbp_client.list_nat_pools()['nat_pools']]
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Fetching NAT Pool List, failed")
            return 0
        if getdict:
            return name_uuid
        else:
            return natpool_list

    @atomic.action_timer("gbp.update_nat_pool")
    def update_gbp_nat_pool(self, gbp_client, uuid, **kwargs):
        """
		Update a NAT Pool
		Supported keywords based attributes and their values/type:
		'ip_pool' = string(must be exact or subnet of cidr)
		'external_segment_id' = string(name/uuid)
		"""
        nat_pool = {}
        try:
            for arg, val in kwargs.items():
                nat_pool[arg] = val
            body = {"nat_pool": nat_pool}
            gbp_client.update_nat_pool(uuid, body)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Update of NAT Pool = %s, failed" % uuid)
            return 0

    @atomic.action_timer("gbp.create_network_service_policy")
    def create_gbp_network_service_policy(self, gbp_client, name, shared=False):
        """
		Create Network Service Policy
		"""
        network_service_params = [{"type": "ip_pool",
                                   "name": "nat",
                                   "value": "nat_pool"}]
        nsp_nat = {'name': name, 'network_service_params': network_service_params, 'shared': shared}
        try:
            body = {'network_service_policy': nsp_nat}
            nsp_nat_uuid = gbp_client.create_network_service_policy(body)['network_service_policy']['id'].encode(
                'ascii')
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Creating NAT NSP failed")
            return 0
        return nsp_nat_uuid

    @atomic.action_timer("gbp.update_network_service_policy")
    def update_gbp_network_service_policy(self, gbp_client, uuid):
        """
		Update a Network Service Policy
		"""
        nsp_nat = {}
        try:
            body = {'network_service_policy': nsp_nat}
            gbp_client.update_network_service_policy(uuid, body)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Update of Network Service Policy = %s, failed" % uuid)
            return 0

    @atomic.action_timer("gbp.delete_network_service_policy")
    def delete_gbp_network_service_policy(self, gbp_client, nspuuid=''):
        """
		Delete Network Service Policy
		"""
        try:
            if nspuuid != '':
                gbp_client.delete_network_service_policy(nspuuid)
            else:
                nsp_list = gbp_client.list_network_service_policies()['network_service_policies']
                for nsp in nsp_list:
                    nspuuid = nsp['id']
                    gbp_client.delete_network_service_policy(nspuuid)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Deleting NAT NSP = %s, failed" % nspuuid)
            return 0

    @atomic.action_timer("gbp.list_network_service_policy")
    def get_gbp_network_service_policy_list(self, gbp_client, getdict=False):
        """
		Fetch a List of GBP Network Service Policy
		getdict: 'True', will return a dictionary comprising 'name' & 'uuid'
		"""
        try:
            if getdict:
                name_uuid = {}
                for nsp in gbp_client.list_network_service_policies()['network_service_policies']:
                    name_uuid[nsp['name'].encode('ascii')] = nsp['id'].encode('ascii')
            else:
                nsp_list = [item['id'] for item in
                            gbp_client.list_network_service_policies()['network_service_policies']]
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Fetching Network Service Policy List, failed")
            return 0
        if getdict:
            return name_uuid
        else:
            return nsp_list

    @atomic.action_timer("gbp.create_external_policy")
    def create_gbp_external_policy(self, gbp_client, name, **kwargs):
        """
		Create the External Policy
		Provide uniform property_type('name' or 'uuid') across objects
		Pass external_segments as a List
		"""

        try:
            external_policy = {"name": name}
            for arg, val in kwargs.items():
                external_policy[arg] = val
            body = {"external_policy": external_policy}
            extpol_uuid = gbp_client.create_external_policy(body)['external_policy']['id'].encode('ascii')
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Creating External Policy = %s, failed" % name)
            return 0
        return extpol_uuid

    @atomic.action_timer("gbp.update_external_policy")
    def update_gbp_external_policy(self, gbp_client,
                                   name_uuid,
                                   property_type='name',
                                   consumed_policy_rulesets='',
                                   provided_policy_rulesets='',
                                   external_segments=[],
                                   shared=False):
        """
		Update the External Policy
		Provide uniform property_type('name' or 'uuid')
		across objects EXCEPT external_segments(only id)
		Pass external_segments as a List
		"""
        try:
            consumed_prs = {}
            provided_prs = {}
            if property_type == 'name':
                policy_id = self.verify_gbp_external_policy(gbp_client, name_uuid)
                if consumed_policy_rulesets:
                    for ruleset in consumed_policy_rulesets:
                        id = self.verify_gbp_policy_rule_set(gbp_client, ruleset)
                        consumed_prs[id] = "scope"
                if provided_policy_rulesets:
                    for ruleset in provided_policy_rulesets:
                        id = self.verify_gbp_policy_rule_set(gbp_client, ruleset)
                        provided_prs[id] = "scope"
            else:
                policy_id = name_uuid
                if consumed_policy_rulesets:
                    for ruleset in consumed_policy_rulesets:
                        consumed_prs[ruleset] = "scope"
                if provided_policy_rulesets:
                    for ruleset in provided_policy_rulesets:
                        provided_prs[ruleset] = "scope"
            body = {"external_policy": {"shared": shared}}
            while True:
                if consumed_policy_rulesets and provided_policy_rulesets:
                    body["external_policy"]["provided_policy_rule_sets"] = provided_prs
                    body["external_policy"]["consumed_policy_rule_sets"] = consumed_prs
                    if external_segments:
                        body["external_policy"]["external_segments"] = external_segments
                    break
                elif consumed_policy_rulesets and not provided_policy_rulesets:
                    body["external_policy"]["consumed_policy_rule_sets"] = consumed_prs
                    if external_segments:
                        body["external_policy"]["external_segments"] = external_segments
                    break
                elif not consumed_policy_rulesets and provided_policy_rulesets:
                    body["external_policy"]["provided_policy_rule_sets"] = provided_prs
                    if external_segments:
                        body["external_policy"]["external_segments"] = external_segments
                    break
                elif not provided_policy_rulesets and not consumed_policy_rulesets:
                    if external_segments:  # only when ExtSeg gets changed, keeping PRS intact
                        body["external_policy"]["external_segments"] = external_segments
                        break
                    else:
                        body["external_policy"]["provided_policy_rule_sets"] = provided_prs
                        body["external_policy"]["consumed_policy_rule_sets"] = consumed_prs
                    break
                else:
                    break
            gbp_client.update_external_policy(policy_id, body)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Updating External Policy = %s, failed" % name_uuid)
            return 0

    @atomic.action_timer("gbp.delete_external_policy")
    def delete_gbp_external_policy(self, gbp_client, uuid):
        """
		 Delete a GBP External Policy
		 """
        try:
            gbp_client.delete_external_policy(uuid)
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Deleting External Policy %s, failed" % uuid)
            return 0

    @atomic.action_timer("gbp.list_external_policy")
    def get_gbp_external_policy_list(self, gbp_client, getdict=False):
        """
		Fetch a List of GBP External Policies
		getdict: 'True', will return a dictionary comprising 'name' & 'uuid'
		"""
        try:
            if getdict:
                name_uuid = {}
                for extpol in gbp_client.list_external_policies()['external_policies']:
                    name_uuid[extpol['name'].encode('ascii')] = extpol['id'].encode('ascii')
            else:  # Return list of ids
                extpol_list = [item['id'] for item in gbp_client.list_external_policies()['external_policies']]
        except Exception as e:
            _log.error("\nException Error: %s\n" % e)
            _log.error("Fetching External Policies List, failed")
            return 0
        if getdict:
            return name_uuid
        else:
            return extpol_list

    @atomic.action_timer("gbp.verify_external_policy")
    def verify_gbp_external_policy(self, gbp_client, name):
        """
		Verify the GBP External Policy by passing its name and fetch its UUID
		"""
        for extpol in gbp_client.list_external_policies()['external_policies']:
            if extpol['name'].encode('ascii') == name:
                return extpol['id'].encode('ascii')
        _log.error("External Policy Group NOT Found")
        return 0

    @atomic.action_timer("gbp.verify_any_object")
    def verify_gbp_any_object(self, gbp_client, obj, obj_uuid, **kwargs):
        """
		Verify any objects and its attributes
		Pass the keywords as it appears in a show cmd
		Valid objects are:: l3_policy,l2_policy,policy_target_group,
		policy_target,nat_pool,external_segment,external_policy and
		others as it appears in a gbp show CLI
		keywords:: the string should be exact as seen in gbp show CLI
		values:: should be passed as the datatype as it appears in CLI
		Example: For obj: l3_policy, key=l2_policies, val=['uuid of l2p']
		"""
        if obj == 'l3_policy':
            attributes = gbp_client.show_l3_policy(obj_uuid)[obj]
            for arg, val in kwargs.items():
                if arg == 'external_segments':
                    # TODO: will revist this to handle single L3P
                    # associated to multiple ExtSeg.
                    if val not in attributes[arg].keys():
                        return 0
                else:
                    if isinstance(val, list) and isinstance(attributes[arg], list):
                        if set(attributes[arg]) != set(val):
                            _log.error(
                                "Attribute %s and its Value %s NOT found in Object %s %s" % (arg, val, obj, obj_uuid))
                            return 0
                    if isinstance(attributes[arg], list) and isinstance(val, str):
                        if val not in attributes[arg]:
                            _log.error(
                                "Attribute %s and its Value %s NOT found in Object %s %s" % (arg, val, obj, obj_uuid))
                            return 0
        if obj == 'l2_policy':
            attributes = gbp_client.show_l2_policy(obj_uuid)[obj]
            for arg, val in kwargs.items():
                if arg == 'policy_target_groups':
                    if val not in attributes[arg]:
                        _log.error(
                            "Attribute %s and its Value %s NOT found in Object %s %s" % (arg, val, obj, obj_uuid))
                        return 0
                else:
                    if attributes[arg] != val:
                        _log.error(
                            "Attribute %s and its Value %s NOT found in Object %s %s" % (arg, val, obj, obj_uuid))
                        return 0
        if obj == 'policy_target_group':
            attributes = gbp_client.show_policy_target_group(obj_uuid)[obj]
            for arg, val in kwargs.items():
                if isinstance(val, list) and isinstance(attributes[arg], list):
                    unmatched = [item for item in val if item not in attributes[arg]]
                    if len(unmatched) > 0:
                        _log.error(
                            "Attribute %s and its Value %s NOT found in Object %s %s" % (arg, val, obj, obj_uuid))
                        return 0
                elif isinstance(attributes[arg], list) and isinstance(val, str):
                    if val not in attributes[arg]:
                        _log.error(
                            "Attribute %s and its Value %s NOT found in Object %s %s" % (arg, val, obj, obj_uuid))
                        return 0
                else:
                    if attributes[arg] != val:
                        _log.error(
                            "Attribute %s and its Value %s NOT found in Object %s %s" % (arg, val, obj, obj_uuid))
                        return 0
        if obj == 'external_segment':
            attributes = gbp_client.show_external_segment(obj_uuid)[obj]
            for arg, val in kwargs.items():
                if isinstance(val, list) and isinstance(attributes[arg], list):
                    unmatched = [item for item in val if item not in attributes[arg]]
                    if len(unmatched) > 0:
                        _log.error(
                            "Attribute %s and its Value %s NOT found in Object %s %s" % (arg, val, obj, obj_uuid))
                        return 0
                elif isinstance(attributes[arg], list) and isinstance(val, str):
                    if val not in attributes[arg]:
                        _log.error(
                            "Attribute %s and its Value %s NOT found in Object %s %s" % (arg, val, obj, obj_uuid))
                        return 0
                else:
                    if attributes[arg] != val:
                        _log.error(
                            "Attribute %s and its Value %s NOT found in Object %s %s" % (arg, val, obj, obj_uuid))
                        return 0
        if obj == 'external_policy':
            attributes = gbp_client.show_external_policy(obj_uuid)[obj]
            for arg, val in kwargs.items():
                if attributes[arg] != val:
                    _log.error("Attribute %s and its Value %s NOT found in Object %s %s" % (arg, val, obj, obj_uuid))
                    return 0

    @atomic.action_timer("gbp.add_route_in_shadow_l3out")
    def addrouteinshadowl3out(self, gbp_client, extseg_id, extseg_name, nattype, destrte, route=''):
        """
		Utility Method to add ext_routes to Ext_Seg
		ONLY needed for NAT DP TESTs ONLY USED For secondary L3 Out ExtSeg
		TBD: To be enhanced
		"""
        if extseg_name == "L3OUT2":
            route_gw = ''
        if nattype == 'dnat' and route != '':
            _log.info("\nRoute added to ShadowL3Out corresponding to External Segment"
                      " %s for DNAT VM2VM Traffic are %s & %s with GW %s" \
                      % (extseg_name, route, destrte, route_gw))
            self.update_gbp_external_segment(gbp_client,
                                             extseg_id, external_routes=[{'destination': route, 'nexthop': route_gw},
                                                                         {'destination': destrte, 'nexthop': route_gw}])
        if nattype == 'dnat' and route == '':
            _log.info("\nRoute added to ShadowL3Out corresponding to External "
                      "Segment%s for DNAT ExtRtr2VM Traffic is %s with GW %s" \
                      % (extseg_name, destrte, route_gw))
            self.update_gbp_external_segment(gbp_client,
                                             extseg_id, external_routes=[{'destination': destrte, 'nexthop': route_gw}])
        if nattype == 'snat':
            _log.info("\nRoute added to ShadowL3Out corresponding to"
                      " External Segment %s for SNAT Traffic is %s with GW %s" \
                      % (extseg_name, destrte, route_gw))
            self.update_gbp_external_segment(gbp_client,
                                             extseg_id, external_routes=[{'destination': destrte, 'nexthop': route_gw}])

    @atomic.action_timer("gbp.cleanup_all")
    def cleanup_gbp(self, gbp_client):

        try:
            pt_list = self.get_gbp_policy_target_list(gbp_client)
            if len(pt_list):
                for pt in pt_list:
                    self.delete_gbp_policy_target(gbp_client, pt, property_type='uuid')
            ptg_list = self.get_gbp_policy_target_group_list(gbp_client)
            if len(ptg_list):
                for ptg in ptg_list:
                    self.delete_gbp_policy_target_group(gbp_client, ptg, property_type='uuid')
            l2p_list = self.get_gbp_l2policy_list(gbp_client)
            if len(l2p_list):
                for l2p in l2p_list:
                    self.delete_gbp_l2policy(gbp_client, l2p, property_type='uuid')
            l3p_list = self.get_gbp_l3policy_list(gbp_client)
            if len(l3p_list):
                for l3p in l3p_list:
                    self.delete_gbp_l3policy(gbp_client, l3p, property_type='uuid')
            nsp_list = self.get_gbp_network_service_policy_list(gbp_client)
            if len(nsp_list):
                for nsp in nsp_list:
                    self.delete_gbp_network_service_policy(gbp_client, nsp)
            natpool_list = self.get_gbp_nat_pool_list(gbp_client)
            if len(natpool_list):
                for natpool in natpool_list:
                    self.delete_gbp_nat_pool(gbp_client, natpool)
            extpol_list = self.get_gbp_external_policy_list(gbp_client)
            if len(extpol_list):
                for extpol in extpol_list:
                    self.delete_gbp_external_policy(gbp_client, extpol)
            extseg_list = self.get_gbp_external_segment_list(gbp_client)
            if len(extseg_list):
                for extseg in extseg_list:
                    self.delete_gbp_external_segment(gbp_client, extseg)
            prs_list = self.get_gbp_policy_rule_set_list(gbp_client)
            if len(prs_list) > 0:
                for prs in prs_list:
                    self.delete_gbp_policy_rule_set(gbp_client,
                                                    prs, property_type='uuid')
            pr_list = self.get_gbp_policy_rule_list(gbp_client)
            if len(pr_list) > 0:
                for pr in pr_list:
                    self.delete_gbp_policy_rule(gbp_client,
                                                pr, property_type='uuid')
            cls_list = self.get_gbp_policy_classifier_list(gbp_client)
            if len(cls_list) > 0:
                for cls in cls_list:
                    self.delete_gbp_policy_classifier(gbp_client,
                                                      cls, property_type='uuid')
            act_list = self.get_gbp_policy_action_list(gbp_client)
            if len(act_list) > 0:
                for act in act_list:
                    self.delete_gbp_policy_action(gbp_client,
                                                  act, property_type='uuid')
        except Exception as e:
            print("Exception in Cleanup == ", repr(e))
        pass
