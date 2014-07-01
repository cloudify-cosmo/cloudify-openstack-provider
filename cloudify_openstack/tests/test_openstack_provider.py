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
            'resources_prefix': 'p1',
            'prefix_all_resources_random': True,
        }
        cloudify_openstack.cloudify_openstack.ProviderManager(provider_config,
                                                              False)

    # Utilities

    def _clear_openstack_environment(self):
        env = os.environ
        vars_to_remove = [k for k in env if k.startswith('OS_')]
        for k in vars_to_remove:
            del env[k]
