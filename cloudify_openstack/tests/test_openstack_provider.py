########
# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
############

__author__ = 'barakm'

import unittest
import os
import cloudify_openstack.cloudify_openstack


CONFIG_LOCATIONS_TO_PREFIX = (
    ('networking', 'int_network'),
    ('networking', 'subnet'),
    # ('networking', 'ext_network'),
    ('networking', 'router'),
    ('networking', 'agents_security_group'),
    ('networking', 'management_security_group'),
    ('compute', 'management_server', 'instance'),
)


class OpenStackProviderTest(unittest.TestCase):

    # Overrides from environment

    def test_override_username_from_env(self):
        provider_config = {}
        provider_config["keystone"] = {}
        provider_config["keystone"]["auth_url"] = "http://nowhere"
        # provider_config["keystone"]["username"] = "NO_USER"
        provider_config["keystone"]["password"] = "NO_PASSWORD"

        os.environ["OS_USERNAME"] = "MODIFIED_NAME"
        cloudify_openstack.cloudify_openstack.ProviderManager(provider_config,
                                                              False)
        self.assertEqual(provider_config["keystone"]["username"],
                         "MODIFIED_NAME")

    def test_no_override_username_from_env(self):
        provider_config = {}
        provider_config["keystone"] = {}
        provider_config["keystone"]["auth_url"] = "http://nowhere"
        provider_config["keystone"]["username"] = "NO_USER"
        provider_config["keystone"]["password"] = "NO_PASSWORD"

        os.environ["OS_USERNAME"] = "MODIFIED_NAME"
        cloudify_openstack.cloudify_openstack.ProviderManager(provider_config,
                                                              False)
        self.assertEqual(provider_config["keystone"]["username"], "NO_USER")

    def test_override_all(self):
        provider_config = {}
        provider_config["keystone"] = {}

        os.environ["OS_USERNAME"] = "MODIFIED_NAME"
        os.environ["OS_PASSWORD"] = "MODIFIED_PASSWORD"
        os.environ["OS_TENANT_NAME"] = "MODIFIED_TENANT"
        os.environ["OS_AUTH_URL"] = "MODIFIED_URL"
        os.environ["OS_TENANT_ID"] = "MODIFIED_TENANT_ID"

        cloudify_openstack.cloudify_openstack.ProviderManager(provider_config,
                                                              False)
        self.assertEqual(provider_config["keystone"]["username"],
                         "MODIFIED_NAME")
        self.assertEqual(provider_config["keystone"]["password"],
                         "MODIFIED_PASSWORD")
        self.assertEqual(provider_config["keystone"]["tenant_name"],
                         "MODIFIED_TENANT")
        self.assertEqual(provider_config["keystone"]["auth_url"],
                         "MODIFIED_URL")
        self.assertEqual(provider_config["keystone"]["tenant_id"],
                         "MODIFIED_TENANT_ID")

    def test_override_all_no_keystone(self):
        provider_config = {}

        os.environ["OS_USERNAME"] = "MODIFIED_NAME"
        os.environ["OS_PASSWORD"] = "MODIFIED_PASSWORD"
        os.environ["OS_TENANT_NAME"] = "MODIFIED_TENANT"
        os.environ["OS_AUTH_URL"] = "MODIFIED_URL"
        os.environ["OS_TENANT_ID"] = "MODIFIED_TENANT_ID"

        cloudify_openstack.cloudify_openstack.ProviderManager(provider_config,
                                                              False)
        self.assertEqual(provider_config["keystone"]["username"],
                         "MODIFIED_NAME")
        self.assertEqual(provider_config["keystone"]["password"],
                         "MODIFIED_PASSWORD")
        self.assertEqual(provider_config["keystone"]["tenant_name"],
                         "MODIFIED_TENANT")
        self.assertEqual(provider_config["keystone"]["auth_url"],
                         "MODIFIED_URL")
        self.assertEqual(provider_config["keystone"]["tenant_id"],
                         "MODIFIED_TENANT_ID")

    def test_no_keystone_and_no_env(self):
        provider_config = {}
        self._clear_openstack_environment()
        cloudify_openstack.cloudify_openstack.ProviderManager(provider_config,
                                                              False)
        self.assertNotIn('keystone', provider_config)

    def test_no_keystone_with_env(self):
        provider_config = {}
        os.environ["OS_USERNAME"] = "MODIFIED_NAME"

        cloudify_openstack.cloudify_openstack.ProviderManager(provider_config,
                                                              False)
        self.assertIn('keystone', provider_config)
        self.assertEqual(os.environ["OS_USERNAME"],
                         provider_config['keystone']['username'])

    def test_override_default(self):
        provider_config = {}
        provider_config['keystone'] = {}
        provider_config['keystone']['username'] = \
            'Enter-Openstack-Username-Here'
        provider_config['keystone']['password'] = \
            'Enter-Openstack-Password-Here'
        provider_config['keystone']['tenant_name'] = \
            'Enter-Openstack-Tenant-Name-Here'
        provider_config['keystone']['auth_url'] = \
            'Enter-Openstack-Auth-Url-Here'

        self._clear_openstack_environment()
        os.environ["OS_USERNAME"] = "MODIFIED_NAME"
        os.environ["OS_PASSWORD"] = "MODIFIED_PASSWORD"
        os.environ["OS_TENANT_NAME"] = "MODIFIED_TENANT"
        os.environ["OS_AUTH_URL"] = "MODIFIED_URL"

        cloudify_openstack.cloudify_openstack.ProviderManager(provider_config,
                                                              False)
        self.assertIn('keystone', provider_config)
        self.assertEqual(provider_config["keystone"]["username"],
                         "MODIFIED_NAME")
        self.assertEqual(provider_config["keystone"]["password"],
                         "MODIFIED_PASSWORD")
        self.assertEqual(provider_config["keystone"]["tenant_name"],
                         "MODIFIED_TENANT")
        self.assertEqual(provider_config["keystone"]["auth_url"],
                         "MODIFIED_URL")

    # Prefixing

    def test_prefix_non_existing(self):
        """ Just see that there is no exception thrown """
        provider_config = {
            'prefix_for_all_resources': 'p1',
            'prefix_all_resources_random': True,
        }
        cloudify_openstack.cloudify_openstack.ProviderManager(provider_config,
                                                              False)

    def test_prefix_static(self):
        provider_config = self._get_provider_config_for_prefix_tests()
        provider_config['prefix_for_all_resources'] = 'p1'
        provider_config['prefix_all_resources_random'] = False
        cloudify_openstack.cloudify_openstack.ProviderManager(provider_config,
                                                              False)
        self._assert_prefixed_locations_match(
            provider_config, lambda l: 'p1_' + l.upper())

    def test_prefix_random(self):
        provider_config = self._get_provider_config_for_prefix_tests()
        provider_config['prefix_all_resources_random'] = True
        cloudify_openstack.cloudify_openstack.ProviderManager(provider_config,
                                                              False)
        self._assert_prefixed_locations_match(
            provider_config, lambda l: '[0-9]+_' + l.upper())

    def test_prefix_static_and_random(self):
        provider_config = self._get_provider_config_for_prefix_tests()
        provider_config['prefix_for_all_resources'] = 'p1'
        provider_config['prefix_all_resources_random'] = True
        cloudify_openstack.cloudify_openstack.ProviderManager(provider_config,
                                                              False)
        self._assert_prefixed_locations_match(
            provider_config, lambda l: 'p1_[0-9]+_' + l.upper())

    # Utilities

    def _clear_openstack_environment(self):
        env = os.environ
        vars_to_remove = [k for k in env if k.startswith('OS_')]
        for k in vars_to_remove:
            del env[k]

    def _get_provider_config_for_prefix_tests(self):
        cfg = {}
        for path in CONFIG_LOCATIONS_TO_PREFIX:
            item = self._create_nested_hashes(cfg, path)
            item['name'] = path[-1].upper()
        return cfg

    def _create_nested_hashes(self, h, path):
        if not path:
            return h
        h[path[0]] = h.get(path[0], {})
        return self._create_nested_hashes(h[path[0]], path[1:])

    def _traverse_nested_hashes(self, h, path):
        if not path:
            return h
        return self._traverse_nested_hashes(h[path[0]], path[1:])

    def _assert_prefixed_locations_match(self, provider_config, f):
        """ Asserts that all 'name's in CONFIG_LOCATIONS_TO_PREFIX
        locations of 'provider_config' match the regex returned by 'f' """
        for path in CONFIG_LOCATIONS_TO_PREFIX:
            item = self._traverse_nested_hashes(provider_config, path)
            self.assertRegexpMatches(item['name'], '^' + f(path[-1]) + '$')
