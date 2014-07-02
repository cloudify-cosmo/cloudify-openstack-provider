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

__author__ = 'ran'

# Standard
import os
import errno
import inspect
import itertools
import re
import time
import urllib
import json
import shutil
from getpass import getuser
from os.path import expanduser
from fabric.api import put, env
from fabric.context_managers import settings
import tempfile
import platform

# Validator
from IPy import IP
from schemas import PROVIDER_CONFIG_SCHEMA

# OpenStack
import keystoneclient.v2_0.client as keystone_client
import novaclient.v1_1.client as nova_client
import neutronclient.neutron.client as neutron_client

# from CLI
# provides a logger to be used throughout the provider code
# returns a tuple of a main (file+console logger) and a file
# (file only) logger.
from cosmo_cli.cosmo_cli import init_logger
# provides a way to set the global verbosity level
# from cosmo_cli.cosmo_cli import set_global_verbosity_level
# provides 2 base methods to be used.
# if not imported, the bootstrap method must be implemented
from cosmo_cli.provider_common import BaseProviderClass

# declare the create_if_missing flag
CREATE_IF_MISSING = 'create_if_missing'

# declare which ports should be opened during provisioning
EXTERNAL_MGMT_PORTS = (22, 8100, 80)  # SSH, REST service (TEMP), REST and UI
INTERNAL_MGMT_PORTS = (5555, 5672, 53229)  # Riemann, RabbitMQ, FileServer
INTERNAL_AGENT_PORTS = (22,)

# declare default verbosity state
verbose_output = False
# declare os types for validation checks
linuxd = ('Linux')
wind = ('Windows')

# initialize logger
lgr, flgr = init_logger()


class ProviderManager(BaseProviderClass):
    """class for base methods name must be kept as is.

    inherits BaseProviderClass from the cli containing the following
    methods:

    __init__: initializes base mandatory params provider_config and
    is_verbose_output. additionally, optionally receives a schema param
    that enables the default schema validation method to be executed.

    bootstrap: installs cloudify on the management server.

    validate_config_schema: validates a schema file against the provider
    configuration file supplied with the provider module.
    (for more info on BaseProviderClass, see the CLI's documentation.)

    ProviderManager classes:

    - __init__: *optional* - only if more params are initialized
    - provision: *mandatory*
    - validate: *mandatory*
    - teardown: *mandatory*
    """

    schema = PROVIDER_CONFIG_SCHEMA

    # Resources to prefix
    # In each one of them, the "name" is prefixed.
    CONFIG_NAMES_TO_MODIFY = (
        ('networking', 'int_network'),
        ('networking', 'subnet'),
        # ('networking', 'ext_network'),
        ('networking', 'router'),
        ('networking', 'agents_security_group'),
        ('networking', 'management_security_group'),
        ('compute', 'agent_servers', 'agents_keypair'),
        ('compute', 'management_server', 'instance'),
        ('compute', 'management_server', 'management_keypair'),
    )

    CONFIG_FILES_PATHS_TO_MODIFY = (
        ('compute', 'agent_servers', 'agents_keypair',
            'auto_generated', 'private_key_target_path'),
        ('compute', 'agent_servers', 'agents_keypair',
            'provided', 'private_key_filepath'),
        ('compute', 'agent_servers', 'agents_keypair',
            'provided', 'public_key_filepath'),
        ('compute', 'management_server', 'management_keypair',
            'auto_generated', 'private_key_target_path'),
        ('compute', 'management_server', 'management_keypair',
            'provided', 'private_key_filepath'),
        ('compute', 'management_server', 'management_keypair',
            'provided', 'public_key_filepath'),
    )

    def __init__(self, provider_config, is_verbose_output):
        """
        initializes base params.

        provider_config and is_verbose_output are initialized in the
        base class and are mandatory. if more params are needed, super can
        be used to init a different provider_config and is_verbose_output.

        "schema" is an optional parameter containing a jsonschema
        object (dict). If initialized it will automatically trigger schema
        validation for the provider. Schema validation will be performed
        using the default validate_schema method (from the base class).
        a new "validate_schema" method can be supplied if needed to replace
        the default one.

        :param dict provider_config: inherits the config yaml from the cli
        :param bool is_verbose_output: self explanatory
        :param dict schema: json schema for validation
        """

        self._modify_keystone_from_environment(provider_config, os.environ)

        super(ProviderManager, self).__init__(provider_config,
                                              is_verbose_output)

    def _modify_keystone_from_environment(self, config, environ):
        keystone_exists = False
        keystone_config = config.get('keystone', None)
        if keystone_config is not None:
            keystone_exists = True
        else:
            keystone_config = {}

        self._modify_key_by_environ(keystone_config, "username", environ,
                                    "OS_USERNAME",
                                    ["Enter-Openstack-Username-Here", ''])
        self._modify_key_by_environ(keystone_config, "password", environ,
                                    "OS_PASSWORD",
                                    ["Enter-Openstack-Password-Here", ''])
        self._modify_key_by_environ(keystone_config, "tenant_name", environ,
                                    "OS_TENANT_NAME",
                                    ["Enter-Openstack-Tenant-Name-Here", ''])
        self._modify_key_by_environ(keystone_config, "tenant_id", environ,
                                    "OS_TENANT_ID", [''])
        self._modify_key_by_environ(keystone_config, "auth_url", environ,
                                    "OS_AUTH_URL",
                                    ['Enter-Openstack-Auth-Url-Here', ''])

        if not keystone_exists:
            if len(keystone_config) > 0:
                config['keystone'] = keystone_config

    def _modify_key_by_environ(self, dict, key, environ,
                               env_var_name, default_values):
        if dict.get(key, None) is None or dict[key] in default_values:
            if env_var_name in environ:
                dict[key] = environ[env_var_name]

    def provision(self):
        """
        provisions resources for the management server

        returns a tuple with the machine's public and private ip's,
        the ssh key and user configured in the config yaml and
        the prorivder's context (a dict containing the privisioned
        resources to be used during teardown)

        the tuple's order should correspond with the above order.

        :rtype: 'tuple' with machine context.
        """
        driver = self._get_driver(self.provider_config)
        public_ip, private_ip, ssh_key, ssh_user, provider_context = \
            driver.create_topology()
        return public_ip, private_ip, ssh_key, ssh_user, provider_context

    def bootstrap(self, mgmt_ip, private_ip, mgmt_ssh_key, mgmt_ssh_user,
                  dev_mode=False):
        driver = self._get_driver(self.provider_config)
        driver.copy_files_to_manager(mgmt_ip, mgmt_ssh_key, mgmt_ssh_user)
        return super(ProviderManager, self).bootstrap(
            mgmt_ip, private_ip, mgmt_ssh_key, mgmt_ssh_user, dev_mode)

    def validate(self):
        """
        validations to be performed before provisioning and bootstrapping
        the management server.

        returns a dict of lists of validation errors. each list corresponds
        with a logical section of the validations (e.g, compute, networking..)

        Note: provisioning will continue only if the returned dict is empty.

        :param dict validation_errors: a dict to append the validation errors
         to.
        :rtype: 'dict' of validation_errors.
        """
        # get openstack clients
        connector = OpenStackConnector(self.provider_config)
        # get verifier object
        verifier = OpenStackValidator(connector.get_nova_client(),
                                      connector.get_neutron_client(),
                                      connector.get_keystone_client())

        # get config
        # keystone_config = provider_config['keystone']
        networking_config = self.provider_config['networking']
        compute_config = self.provider_config['compute']
        # cloudify_config = provider_config['cloudify']
        mgmt_server_config = compute_config['management_server']
        agent_server_config = compute_config['agent_servers']
        # mgmt_instance_config = mgmt_server_config['instance']
        mgmt_keypair_config = mgmt_server_config['management_keypair']
        agent_keypair_config = agent_server_config['agents_keypair']

        # validate
        verifier.validate_cidr_syntax(
            'networking.subnet.cidr',
            networking_config['subnet']['cidr'])
        verifier.validate_cidr_syntax(
            'networking.management_security_group.cidr',
            networking_config['management_security_group']['cidr'])

        lgr.info('validating networking resources...')
        if 'neutron_url' in networking_config:
            verifier.validate_url_accessible(
                'networking.network_url',
                networking_config['neutron_url'])
        if 'router' in networking_config:
            verifier.validate_neutron_resource(
                'networking.router.name',
                networking_config['router'],
                resource_type='router',
                method='list_routers')
        verifier.validate_neutron_resource(
            'networking.subnet.name',
            networking_config['subnet'],
            resource_type='subnet',
            method='list_subnets')
        verifier.validate_neutron_resource(
            'networking.int_network.name',
            networking_config['int_network'],
            resource_type='network',
            method='list_networks')
        if 'agents_security_group' in networking_config:
            verifier.validate_neutron_resource(
                'networking.agents_security_group.name',
                networking_config['agents_security_group'],
                resource_type='security_group',
                method='list_security_groups')
        verifier.validate_neutron_resource(
            'networking.management_security_group.name',
            networking_config['management_security_group'],
            resource_type='security_group',
            method='list_security_groups')

        lgr.info('validating compute resources...')
        if 'floating_ip' in mgmt_server_config \
                and verifier.validate_cidr_syntax(
                    'compute.management_server.floating_ip',
                    mgmt_server_config['floating_ip']):
            verifier.validate_floating_ip(
                'compute.management_server.floating_ip',
                mgmt_server_config['floating_ip'])
        else:
            verifier.validate_floating_ip(
                'compute.management_server.floating_ip',
                None)
        verifier.validate_image_exists(
            'compute.management_server.instance.image',
            mgmt_server_config['instance']['image'])
        verifier.validate_flavor_exists(
            'compute.management_server.instance.flavor',
            mgmt_server_config['instance']['flavor'])
        if platform.system() in linuxd:
            if verifier.check_key_exists(
                mgmt_keypair_config['auto_generated']
                                   ['private_key_target_path']):
                verifier.validate_key_perms(
                    'compute.management_server.management_keypair'
                    '.auto_generated.private_key_target_path',
                    mgmt_keypair_config['auto_generated']
                                       ['private_key_target_path'])
                verifier.validate_path_owner(
                    'compute.management_server.management_keypair'
                    '.auto_generated.private_key_target_path',
                    mgmt_keypair_config['auto_generated']
                                       ['private_key_target_path'])
            if verifier.check_key_exists(
                agent_keypair_config['auto_generated']
                                    ['private_key_target_path']):
                verifier.validate_key_perms(
                    'compute.agent_servers.agents_keypair'
                    '.auto_generated.private_key_target_path',
                    agent_keypair_config['auto_generated']
                                        ['private_key_target_path'])
                verifier.validate_path_owner(
                    'compute.agent_servers.agents_keypair'
                    '.auto_generated.private_key_target_path',
                    agent_keypair_config['auto_generated']
                                        ['private_key_target_path'])

        # TODO: check cloudify package url accessiblity from
        # within the instance
        # lgr.info('validating cloudify resources...')
        # verifier.validate_url_accessible(
        #     'cloudify.cloudify_components_package_url',
        #     cloudify_config['cloudify_components_package_url'])
        # verifier.validate_url_accessible(
        #     'cloudify.cloudify_package_url',
        #     cloudify_config['cloudify_package_url'])

        # TODO:
        # verifier.validate_security_rules()
        # undeliverable due to keystone client bug
        # verifier.validate_keystone_service_exists('nova')
        # verifier.validate_keystone_service_exists('neutron')
        # undeliverable due to nova client bug
        # verifier.validate_instance_quota()

        validation_errors = verifier.validation_errors

        lgr.error('resource validation failed!') if validation_errors \
            else lgr.info('resources validated successfully')
        # print json.dumps(validation_errors, sort_keys=True,
        #                  indent=4, separators=(',', ': '))
        return validation_errors

    def teardown(self, provider_context, ignore_validation=False):
        """
        tears down the management server and its accompanied provisioned
        resources

        :param dict provider_context: context information with the previously
         provisioned resources
        :param bool ignore_validation: should the teardown process ignore
         conflicts during teardown
        :rtype: 'None'
        """
        driver = self._get_driver(self.provider_config, provider_context)
        driver.delete_topology(ignore_validation)

    def _get_driver(self, provider_config, provider_context=None):
        """
        comfort driver for provisioning and teardown.
        this is not a mandatory method.
        """
        provider_context = provider_context or {}
        connector = OpenStackConnector(provider_config)
        network_controller = OpenStackNetworkController(connector)
        subnet_controller = OpenStackSubnetController(connector)
        router_controller = OpenStackRouterController(connector)
        floating_ip_controller = OpenStackFloatingIpController(connector)
        keypair_controller = OpenStackKeypairController(connector)
        server_controller = OpenStackServerController(connector)
        if provider_config['networking']['neutron_supported_region']:
            sg_controller = OpenStackNeutronSecurityGroupController(connector)
        else:
            sg_controller = OpenStackNovaSecurityGroupController(connector)
        driver = CosmoOnOpenStackDriver(
            provider_config, provider_context, network_controller,
            subnet_controller, router_controller, sg_controller,
            floating_ip_controller, keypair_controller, server_controller)
        return driver


def _format_resource_name(res_type, res_id, res_name=None):
    if res_name:
        return "{0} - {1} - {2}".format(res_type, res_id, res_name)
    else:
        return "{0} - {1}".format(res_type, res_id)


class OpenStackValidator:
    """
    for every mandatory config element, we'll verify access or existence.

    for every config element that is marked as create_if_missing = False
    we'll verify that the element exists and if it doesn't, alert.

    for every config element that is marked as create_if_missing = True
    we'll check if the element exists and if it doesn't, check if there's
    quota to create the element, and if there isn't, alert.
    """
    def __init__(self, nova_client, neutron_client, keystone_client):
        self.validation_errors = {}
        self.nova_client = nova_client
        self.neutron_client = neutron_client
        self.keystone_client = keystone_client

    def _get_neutron_quota(self, resource):
        quotas = self.neutron_client.show_quota(
            self.keystone_client.tenant_id)['quota']
        return quotas[resource]

    def validate_floating_ip(self, field, floating_ip):
        ips = self.neutron_client.list_floatingips()
        ips_amount = len(ips['floatingips'])
        if floating_ip is not None:
            lgr.debug('checking whether floating_ip {0} exists...'
                      .format(floating_ip))
            found_floating_ip = False
            for ip in ips['floatingips']:
                if ip['floating_ip_address'] == floating_ip:
                    lgr.debug('OK:'
                              'floating_ip {0} is allocated'
                              .format(floating_ip))
                    found_floating_ip = True
                    break
            if not found_floating_ip:
                err = ('config file validation error originating at key: {0}, '
                       'floating_ip {1} is not allocated.'
                       ' please provide an allocated address'
                       ' or comment the floating_ip line in the config'
                       ' and one will be allocated for you.'
                       .format(field, floating_ip))
                lgr.error('VALIDATION ERROR:' + err)
                lgr.info('list of available floating ips:')
                for ip in ips['floatingips']:
                    lgr.info('    {0}'.format(ip['floating_ip_address']))
                self.validation_errors.setdefault('networking', []).append(err)
                return False
            return True
        else:
            lgr.debug('checking whether quota allows allocation'
                      ' of new floating ips')
            ips_quota = self._get_neutron_quota('floatingip')
            if ips_amount < ips_quota:
                lgr.debug('OK:'
                          'a new ip can be allocated.'
                          ' provisioned ips: {0}, quota: {1}'
                          .format(ips_amount, ips_quota))
                return True
            else:
                err = ('config file validation error originating at key: {0}, '
                       'a floating ip cannot be allocated due'
                       ' to quota limitations.'
                       ' privisioned ips: {1}, quota: {2}'
                       .format(field, ips_amount, ips_quota))
                lgr.error('VALIDATION ERROR:' + err)
                self.validation_errors.setdefault('networking', []).append(err)
                return False

    def validate_neutron_resource(self, field, resource_config, resource_type,
                                  method):
        lgr.debug('checking whether {0} {1} exists...'
                  .format(resource_type, resource_config['name']))
        resource_dict = getattr(self.neutron_client, method)()
        resource_amount = len(resource_dict.values()[0])
        for resource in resource_dict.values()[0]:
            if resource['name'] == resource_config['name']:
                lgr.debug('OK:'
                          '{0} {1} found in pool'
                          .format(resource_type, resource_config['name']))
                return True
        if not resource_config[CREATE_IF_MISSING]:
            err = ('config file validation error originating at key: {0}, '
                   '{1} {2} does not exist in the pool but is marked as'
                   ' create_if_missing = False. please provide an existing'
                   ' resource name or change create_if_missing = True'
                   ' to automatically create a new resource.'
                   .format(field, resource_type, resource_config['name']))
            lgr.error('VALIDATION ERROR:' + err)
            lgr.info('list of available {0}s:'.format(resource_type))
            for type, all in resource_dict.iteritems():
                for resource in all:
                    lgr.info('    {0}'.format(resource['name']))
            self.validation_errors.setdefault('networking', []).append(err)
            return False
        else:
            resource_quota = self._get_neutron_quota(resource_type)
            if resource_amount < resource_quota:
                lgr.debug('OK:'
                          '{0} {1} can be created.'
                          ' privisioned {2}s: {3}, quota: {4}'
                          .format(resource_type, resource_config['name'],
                                  resource_type, resource_amount,
                                  resource_quota))
                return True
            else:
                err = ('config file validation error originating at key: {0}, '
                       '{1} {2} cannot be created due'
                       ' to quota limitations.'
                       ' privisioned {3}s: {4}, quota: {5}'
                       .format(field, resource_type, resource_config['name'],
                               resource_type, resource_amount,
                               resource_quota))
                lgr.error('VALIDATION ERROR:' + err)
                self.validation_errors.setdefault('networking', []).append(err)
                return False

    def validate_cidr_syntax(self, field, cidr):
        lgr.debug('checking whether {0} is a valid address range...'
                  .format(cidr))
        try:
            IP(cidr)
            lgr.debug('OK:'
                      '{0} is a valid address range.'.format(cidr))
            return True
        except ValueError as e:
            err = ('config file validation error originating at key: {0}, '
                   '{1}'.format(field, e.message))
            lgr.error('VALIDATION ERROR:' + err)
            self.validation_errors.setdefault('networking', []).append(err)
            return False

    def validate_image_exists(self, field, image):
        image = str(image)
        lgr.debug('checking whether image {0} exists...'.format(image))
        images = self.nova_client.images.list()
        for i in images:
            if image in i.name or image in i.human_id or image in i.id:
                lgr.debug('OK:'
                          'image {0} exists'.format(image))
                return True
        err = ('config file validation error originating at key: {0}, '
               'image {1} does not exist'.format(field, image))
        lgr.error('VALIDATION ERROR:' + err)
        lgr.info('list of available images:')
        for i in images:
            lgr.info('    {0}'.format(i.name))
        self.validation_errors.setdefault('compute', []).append(err)
        return False

    def validate_flavor_exists(self, field, flavor):
        flavor = str(flavor)
        lgr.debug('checking whether flavor {0} exists...'.format(flavor))
        flavors = self.nova_client.flavors.list()
        for f in flavors:
            if flavor in (f.name, f.human_id, f.id):
                lgr.debug('OK:'
                          'flavor {0} exists'.format(flavor))
                return True
        err = ('config file validation error originating at key: {0}, '
               'flavor {1} does not exist'.format(field, flavor))
        lgr.error('VALIDATION ERROR:' + err)
        lgr.info('list of available flavors:')
        for f in flavors:
            lgr.info('    {0:>10} - {1}'.format(f.id, f.name))
        self.validation_errors.setdefault('compute', []).append(err)
        return False

    def check_key_exists(self, key_path):
        # lgr.debug('checking whether key {0} exists'
        #           .format(key_path))
        key_path = expanduser(key_path)
        return os.path.isfile(key_path)

    def validate_key_perms(self, field, key_path):
        lgr.debug('checking whether key {0} has the right permissions'
                  .format(key_path))
        key_path = expanduser(key_path)
        if not os.access(key_path, os.R_OK | os.W_OK):
            err = ('config file validation error originating at key: {0}, '
                   'ssh key {1} is not readable and/or writeable'.format(
                       field, key_path))
            lgr.error('VALIDATION ERROR:' + err)
            self.validation_errors.setdefault('copmute', []).append(err)
            return False
        lgr.debug('OK:'
                  'ssh key {0} has the correct permissions'.format(key_path))
        return True

    def validate_url_accessible(self, field, package_url):
        lgr.debug('checking whether url {0} is accessible'.format(package_url))
        status = urllib.urlopen(package_url).getcode()
        if not status == 200:
            err = ('config file validation error originating at key: {0}, '
                   'url {1} is not accessible'.format(field, package_url))
            lgr.error('VALIDATION ERROR:' + err)
            self.validation_errors.setdefault('cloudify', []).append(err)
            return False
        lgr.debug('OK:'
                  'url {0} is accessible'.format(package_url))
        return True

    def validate_path_owner(self, field, path):
        lgr.debug('checking whether dir {0} is owned by the current user'
                  .format(path))
        from pwd import getpwnam, getpwuid

        path = expanduser(path)
        user = getuser()
        owner = getpwuid(os.stat(path).st_uid).pw_name
        current_user_id = str(getpwnam(user).pw_uid)
        owner_id = str(os.stat(path).st_uid)

        if not current_user_id == owner_id:
            err = ('config file validation error originating at key: {0}, '
                   '{1} is not owned by the current user'
                   ' (it is owned by {2})'
                   .format(field, path, owner))
            lgr.error('VALIDATION ERROR:' + err)
            self.validation_errors.setdefault('compute', []).append(err)
            return False
        lgr.debug('OK:'
                  '{0} is owned by the current user'.format(path))
        return True


class CosmoOnOpenStackDriver(object):
    """
    in change or provisioning and teardown of resources.
    """
    def __init__(self, provider_config, provider_context, network_controller,
                 subnet_controller, router_controller, sg_controller,
                 floating_ip_controller, keypair_controller,
                 server_controller):
        self.config = provider_config
        self.provider_context = provider_context
        self.network_controller = network_controller
        self.subnet_controller = subnet_controller
        self.router_controller = router_controller
        self.sg_controller = sg_controller
        self.floating_ip_controller = floating_ip_controller
        self.keypair_controller = keypair_controller
        self.server_controller = server_controller

        global verbose_output
        self.verbose_output = verbose_output

    def copy_files_to_manager(self, mgmt_ip, ssh_key, ssh_user):
        def _copy(userhome_on_management,
                  keystone_config, agents_key_path,
                  networking, cloudify_config):
            ssh_config = self.config['cloudify']['bootstrap']['ssh']

            env.user = ssh_user
            env.key_filename = ssh_key
            env.abort_on_prompts = False
            env.connection_attempts = ssh_config['connection_attempts']
            env.keepalive = 0
            env.linewise = False
            env.pool_size = 0
            env.skip_bad_hosts = False
            env.timeout = ssh_config['socket_timeout']
            env.forward_agent = True
            env.status = False
            env.disable_known_hosts = False

            lgr.info('uploading keystone and neutron and files to manager')
            tempdir = tempfile.mkdtemp()

            # TODO: handle failed copy operations
            put(agents_key_path, userhome_on_management + '/.ssh')
            keystone_file_path = _make_keystone_file(tempdir,
                                                     keystone_config)
            put(keystone_file_path, userhome_on_management)
            if networking['neutron_supported_region']:
                neutron_file_path = _make_neutron_file(tempdir,
                                                       networking)
                put(neutron_file_path, userhome_on_management)

            shutil.rmtree(tempdir)

        def _make_json_file(tempdir, file_basename, data):
            file_path = os.path.join(tempdir, file_basename + '.json')
            with open(file_path, 'w') as f:
                json.dump(data, f)
            return file_path

        def _make_keystone_file(tempdir, keystone_config):
            # put default region in keystone_config file
            config = {}
            config.update(keystone_config)
            config.update({'region': self.config['compute']['region']})
            return _make_json_file(tempdir, 'keystone_config', config)

        def _make_neutron_file(tempdir, networking):
            return _make_json_file(tempdir, 'neutron_config', {
                'url': networking['neutron_url']
            })

        def _get_private_key_path_from_keypair_config(keypair_config):
            path = keypair_config['provided']['private_key_filepath'] if \
                'provided' in keypair_config else \
                keypair_config['auto_generated']['private_key_target_path']
            return expanduser(path)

        compute_config = self.config['compute']
        mgmt_server_config = compute_config['management_server']

        with settings(host_string=mgmt_ip):
            _copy(
                mgmt_server_config['userhome_on_management'],
                self.config['keystone'],
                _get_private_key_path_from_keypair_config(
                    compute_config['agent_servers']['agents_keypair']),
                self.config['networking'],
                self.config.get('cloudify', {}))

    def create_topology(self):
        resources = {}
        self.provider_context['resources'] = resources

        compute_config = self.config['compute']
        insconf = compute_config['management_server']['instance']

        is_neutron_supported_region = \
            self.config['networking']['neutron_supported_region']
        if is_neutron_supported_region:
            nconf = self.config['networking']['int_network']
            net_id = self.network_controller\
                .create_or_ensure_exists_log_resources(
                    nconf,
                    nconf['name'],
                    resources,
                    'int_network',
                    False)

            sconf = self.config['networking']['subnet']
            subnet_id = self.subnet_controller.\
                create_or_ensure_exists_log_resources(
                    sconf,
                    sconf['name'],
                    resources,
                    'subnet',
                    False,
                    sconf['ip_version'],
                    sconf['cidr'],
                    sconf['dns_nameservers'],
                    net_id)

            enconf = self.config['networking']['ext_network']
            enet_id = self.network_controller.\
                create_or_ensure_exists_log_resources(
                    enconf,
                    enconf['name'],
                    resources,
                    'ext_network',
                    False,
                    ext=True)

            rconf = self.config['networking']['router']
            self.router_controller.\
                create_or_ensure_exists_log_resources(
                    rconf,
                    rconf['name'],
                    resources,
                    'router',
                    False,
                    interfaces=[{'subnet_id': subnet_id}],
                    external_gateway_info={"network_id": enet_id})

            insconf['nics'] = [{'net-id': net_id}]

        # Security group for Cosmo created instances
        asgconf = self.config['networking']['agents_security_group']
        asg_id, agent_sg_created = self.sg_controller.\
            create_or_ensure_exists_log_resources(
                asgconf,
                asgconf['name'],
                resources,
                'agents_security_group',
                True,
                'Cosmo created machines',
                [])

        # Security group for Cosmo manager, allows created
        # instances -> manager communication
        msgconf = self.config['networking']['management_security_group']
        sg_rules = \
            [{'port': p, 'group_id': asg_id} for p in INTERNAL_MGMT_PORTS] + \
            [{'port': p, 'cidr': msgconf['cidr']} for p in EXTERNAL_MGMT_PORTS]
        msg_id = self.sg_controller.create_or_ensure_exists_log_resources(
            msgconf,
            msgconf['name'],
            resources,
            'management_security_group',
            False,
            'Cosmo Manager',
            sg_rules)

        # Add rules to agent security group. (Happens here because we need
        # the management security group id)
        if agent_sg_created:
            self.sg_controller.add_rules(asg_id,
                                         [{'port': port, 'group_id': msg_id}
                                          for port in INTERNAL_AGENT_PORTS])

        # Keypairs setup
        mgr_kpconf = compute_config['management_server']['management_keypair']
        self.keypair_controller.create_or_ensure_exists_log_resources(
            mgr_kpconf,
            mgr_kpconf['name'],
            resources,
            'management_keypair',
            False,
            private_key_target_path=mgr_kpconf['auto_generated']
                                              ['private_key_target_path'] if
            'auto_generated' in mgr_kpconf else None,
            public_key_filepath=mgr_kpconf['provided']
                                          ['public_key_filepath'] if
            'provided' in mgr_kpconf else None
        )

        agents_kpconf = compute_config['agent_servers']['agents_keypair']
        self.keypair_controller.create_or_ensure_exists_log_resources(
            agents_kpconf,
            agents_kpconf['name'],
            resources,
            'agents_keypair',
            False,
            private_key_target_path=agents_kpconf['auto_generated']
            ['private_key_target_path'] if 'auto_generated' in
                                           agents_kpconf else None,
            public_key_filepath=agents_kpconf['provided']
                                             ['public_key_filepath'] if
            'provided' in agents_kpconf else None
        )

        server_id = self.server_controller.\
            create_or_ensure_exists_log_resources(
                insconf,
                insconf['name'],
                resources,
                'management_server',
                False,
                {k: v for k, v in insconf.iteritems() if k != CREATE_IF_MISSING},  # NOQA
                mgr_kpconf['name'],
                msg_id if is_neutron_supported_region else msgconf['name'],
                compute_config['management_server']['creation_timeout']
            )

        if is_neutron_supported_region:
            network_name = nconf['name']
            if insconf[CREATE_IF_MISSING]:  # new server
                self._attach_floating_ip(
                    compute_config['management_server'], enet_id, server_id,
                    resources)
            else:  # existing server
                ips = self.server_controller.get_server_ips_in_network(
                    server_id, nconf['name'])
                if len(ips) < 2:
                    self._attach_floating_ip(
                        compute_config['management_server'], enet_id,
                        server_id, resources)
        else:
            network_name = 'private'

        ips = self.server_controller.get_server_ips_in_network(server_id,
                                                               network_name)
        private_ip, public_ip = ips[:2]
        ssh_key = mgr_kpconf['auto_generated']['private_key_target_path'] \
            if 'auto_generated' in mgr_kpconf else None
        ssh_user = compute_config['management_server']['user_on_management']
        return public_ip, private_ip, ssh_key, ssh_user, self.provider_context

    def _check_and_handle_delete_conflicts(self, resources):
        all_conflicts = {}

        def check_for_conflicts(resource_name, controller, **kwargs):
            resource_data = resources[resource_name]
            conflicts = {}
            if resource_data['created']:
                conflicts = controller.check_for_delete_conflicts(
                    resource_data['id'], **kwargs)
            all_conflicts[resource_name] = set(conflicts)

        def get_known_resource_id(resource_name):
            return resources[resource_name]['id']

        check_for_conflicts('floating_ip', self.floating_ip_controller)
        check_for_conflicts('management_server', self.server_controller)
        check_for_conflicts('agents_keypair', self.keypair_controller)
        check_for_conflicts('management_keypair', self.keypair_controller)

        known_server_id = get_known_resource_id('management_server')
        check_for_conflicts('management_security_group', self.sg_controller,
                            servers_for_deletion={known_server_id})
        check_for_conflicts('agents_security_group', self.sg_controller,
                            servers_for_deletion={known_server_id})

        known_floating_ip_id = get_known_resource_id('floating_ip')
        check_for_conflicts('router', self.router_controller,
                            floating_ips_for_deletion={known_floating_ip_id})

        # Skipping ext_network - currently not automatically created/deleted.

        known_router_id = get_known_resource_id('router')
        check_for_conflicts('subnet', self.subnet_controller,
                            servers_for_deletion={known_server_id},
                            routers_for_deletion={known_router_id})

        known_subnet_id = get_known_resource_id('subnet')
        check_for_conflicts('int_network', self.network_controller,
                            subnets_for_deletion={known_subnet_id})

        self._propagate_conflicts_on_known_resources(resources, all_conflicts)

        def format_conflict_print(conflicted_resource_name,
                                  conflicts):
            return '\t{0}:\n'\
                   '\t\t{1}'.format(
                       _format_resource_name(
                           resources[conflicted_resource_name]['name'] if
                           'name' in resources[conflicted_resource_name] else
                           resources[conflicted_resource_name]['ip'],
                           resources[conflicted_resource_name]['type'],
                           resources[conflicted_resource_name]['id']),
                       '\t\t'.join(['{0}\n'.format(
                           _format_resource_name(conflict_type,
                                                 conflict_id)) for
                                    conflict_type, conflict_id in conflicts]))

        formatted_conflict_lines_str = ''.join(
            [format_conflict_print(conflicted_resource_name, conflicts)
             for conflicted_resource_name, conflicts in all_conflicts
                .iteritems() if
                len(all_conflicts[conflicted_resource_name]) > 0])
        if len(formatted_conflict_lines_str) > 0:
            lgr.info('Conflicts detected:\n'
                     '{0}'.format(formatted_conflict_lines_str))
            return True
        return False

    def _propagate_conflicts_on_known_resources(self, resources,
                                                all_conflicts):
        # Propagate conflicts to make sure the conflicts output includes
        # all resources which can't be taken down - in this case, due to
        # their dependency on other resources which are known but have
        # conflicts themselves.
        # Note that the propagation here is parallel to the
        # 'known_<resource>' usage when checking for conflicts, and the
        # order of the propagation is the same as the order for checking
        # conflicts.
        if resources['management_security_group']['created']:
            all_conflicts['management_security_group'].update(
                all_conflicts['management_server'])
        if resources['agents_security_group']['created']:
            all_conflicts['agents_security_group'].update(
                all_conflicts['management_server'])
        if resources['subnet']['created']:
            all_conflicts['subnet'].update(
                all_conflicts['management_server'])

        if resources['router']['created']:
            all_conflicts['router'].update(all_conflicts['floating_ip'])

        if resources['subnet']['created']:
            all_conflicts['subnet'].update(all_conflicts['router'])

        if resources['int_network']['created']:
            all_conflicts['int_network'].update(all_conflicts['subnet'])

    def _delete_resources(self, resources):
        deleted_resources = []
        not_found_resources = []
        failed_to_delete_resources = []

        def del_resource(resource_name, controller):
            resource_data = resources[resource_name]
            if resource_data['created']:
                result = controller.delete_resource(resource_data['id'])
                if result is None:
                    failed_to_delete_resources.append(resource_data)
                else:
                    if result:
                        deleted_resources.append(resource_data)
                    else:
                        not_found_resources.append(resource_data)
                    del(resources[resource_name])

        # deleting in reversed order to creation order
        del_resource('floating_ip', self.floating_ip_controller)
        del_resource('management_server', self.server_controller)
        del_resource('agents_keypair', self.keypair_controller)
        del_resource('management_keypair', self.keypair_controller)
        del_resource('management_security_group', self.sg_controller)
        del_resource('agents_security_group', self.sg_controller)
        del_resource('router', self.router_controller)
        # Skipping ext_network - currently not automatically created/deleted.
        del_resource('subnet', self.subnet_controller)
        del_resource('int_network', self.network_controller)

        return (deleted_resources, not_found_resources,
                failed_to_delete_resources)

    def delete_topology(self, ignore_validation=False):
        resources = self.provider_context['resources']

        has_conflicts = self._check_and_handle_delete_conflicts(resources)
        if has_conflicts and not ignore_validation:
            lgr.info('Not going forward with teardown due to '
                     'validation conflicts.')
            return

        deleted_resources, not_found_resources, failed_to_delete_resources =\
            self._delete_resources(resources)

        def format_resources_data_for_print(resources_data):
            return '\t'.join(['{0}\n'.format(
                _format_resource_name(
                    resource_data['name'] if 'name' in resource_data else
                    resource_data['ip'],
                    resource_data['type'],
                    resource_data['id'])) for resource_data in resources_data])

        deleted_resources_print = \
            'Successfully deleted the following resources:\n\t{0}\n' \
            .format(format_resources_data_for_print(deleted_resources))
        not_found_resources_print = \
            "The following resources weren't found:\n\t{0}\n" \
            .format(format_resources_data_for_print(not_found_resources))
        failed_to_delete_resources_print = \
            'Failed to delete the following resources:\n\t{0}' \
            .format(format_resources_data_for_print(
                failed_to_delete_resources))

        lgr.info(
            'Finished deleting topology;\n'
            '{0}{1}{2}'
            .format(
                deleted_resources_print if deleted_resources else '',
                not_found_resources_print if not_found_resources else '',
                failed_to_delete_resources_print if
                failed_to_delete_resources else ''))

    def _attach_floating_ip(self, mgmt_server_conf, enet_id, server_id,
                            resources):
        if 'floating_ip' in mgmt_server_conf:
            floating_ip = mgmt_server_conf['floating_ip']
            floating_ip_id = None
        else:
            floating_ip_obj = self.floating_ip_controller.allocate_ip(enet_id)
            floating_ip = floating_ip_obj['floatingip']['floating_ip_address']
            floating_ip_id = floating_ip_obj['floatingip']['id']

        resources['floating_ip'] = {
            'id': str(floating_ip_id),
            'ip': str(floating_ip),
            'type': 'floating ip',
            'created': 'floating_ip' not in mgmt_server_conf
        }

        lgr.info('attaching IP {0} to the instance'.format(
            floating_ip))
        self.server_controller.add_floating_ip(server_id, floating_ip)
        return floating_ip


class OpenStackLogicError(RuntimeError):
    pass


class BaseController(object):

    def _create(self, name, *args, **kw):
        lgr.debug("Will create {0} '{1}'".format(
            self.__class__.WHAT, name))
        return self.create(name, *args, **kw)

    def _check(self, name, *args, **kw):
        lgr.debug("Checking to see if {0} '{1}' already exists".format(
            self.__class__.WHAT, name))
        if self.list_objects_with_name(name):
            lgr.debug("{0} '{1}' already exists".format(
                self.__class__.WHAT, name))
            return True
        else:
            lgr.debug("{0} '{1}' does not exist".format(
                self.__class__.WHAT, name))
            return False

    def create_or_ensure_exists_log_resources(self, provider_config, name,
                                              resources, resource_name,
                                              return_created, *args,
                                              **kwargs):
        id, created = self._create_or_ensure_exists(provider_config, name,
                                                    *args, **kwargs)
        resources[resource_name] = {
            'id': str(id),
            'type': self.__class__.WHAT,
            'name': name,
            'created': created
        }
        # TODO:
        # replace:
        if return_created:
            return id, created
        else:
            return id
        # with:
        # return id, created if return_created else id

    def delete_resource(self, resource_id, retries=3, sleep=3):
        # Attempts to delete a resource by id (with retries).
        # Returns True if resource deleted successfully,
        # False if resource didn't exist,
        # None if failed to delete existing resource
        res_type = self.__class__.WHAT
        lgr.debug("Attempting to delete resource {0}"
                  .format(_format_resource_name(res_type, resource_id)))
        for retry in range(retries):
            try:
                self.delete(resource_id)
            except Exception as e:
                # Checking if resource doesn't exist
                if self._is_openstack_404_error(e):
                    lgr.debug("resource {0} wasn't found".format(resource_id))
                    return False

                # Different error occurred. Retry or give up.
                lgr.debug("Error while attempting to delete resource "
                          "{0} [retry {1} of {2}]: {3}".format(
                              _format_resource_name(res_type, resource_id),
                              retry, retries, str(e)))
                time.sleep(sleep)
                continue

            try:
                self._wait_for_resource_to_be_deleted(resource_id)
                lgr.debug('resource {0} terminated'.format(resource_id))
                return True
            except Exception as e:
                lgr.debug('Error while waiting for resource {0} '
                          'to terminate: {1}'.format(
                              _format_resource_name(res_type, resource_id),
                              str(e)))
                return None
        lgr.debug('Failed all retries to delete resource {0}'
                  .format(_format_resource_name(res_type, resource_id)))
        return None

    def _wait_for_resource_to_be_deleted(self, resource_id):
        timeout = 20
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self.get_by_id(resource_id)
                lgr.debug('resource {0} is still up'.format(resource_id))
            except Exception as e:
                if self._is_openstack_404_error(e):
                    return
                raise
            time.sleep(2)
        else:
            raise RuntimeError('resource {0} failed to terminate in time'
                               .format(resource_id))

    def _is_openstack_404_error(self, e):
        # It seems like at the moment, exceptions from Neutron for example
        # are general "NeutronError" exceptions rather than a clean
        # neutronclient.common.exceptions.NotFound error, which is
        # why we check for the status code instead.
        # nova in different regions and neutron may use either status_code
        # or http_status fields.
        return hasattr(e, 'status_code') and e.status_code == 404 or \
            hasattr(e, 'http_status') and e.http_status == 404

    def _create_or_ensure_exists(self, provider_config, name, *args, **kw):
        """
        if resource exists:
            if resource is server:
                raise already exists
            use resource
        else:
            if not create_if_missing:
                raise does not exist
            create resource
        """
        if self._check(name, *args, **kw):
            if self.__class__.WHAT in ('server'):
                raise OpenStackLogicError("{0} '{1}' already exists".format(
                                          self.__class__.WHAT, name))
            the_id = self.ensure_exists(name, *args, **kw)
            created = False
        else:
            if not provider_config.get(CREATE_IF_MISSING, True):
                raise OpenStackLogicError("{0} '{1}' does not exist but "
                                          "create_if_missing is false or "
                                          "absent.".format(self.__class__.WHAT,
                                                           name))
            the_id = self._create(name, *args, **kw)
            created = True
        return the_id, created

    def ensure_exists(self, name, *args, **kw):
        lgr.debug("Will use existing {0} '{1}'"
                  .format(self.__class__.WHAT, name))
        ret = self.find_by_name(name)
        if not ret:
            raise OpenStackLogicError("{0} '{1}' was not found".format(
                self.__class__.WHAT, name))
        return ret['id']

    def find_by_name(self, name):
        matches = self.list_objects_with_name(name)

        if len(matches) == 0:
            return None
        if len(matches) == 1:
            return matches[0]
        raise OpenStackLogicError("Lookup of {0} named '{1}' failed. There "
                                  "are {2} matches."
                                  .format(self.__class__.WHAT, name,
                                          len(matches)))

    def _fail_on_missing_required_parameters(self, obj, required_parameters,
                                             hint_where):
        for k in required_parameters:
            if k not in obj:
                raise OpenStackLogicError("Required parameter '{0}' is "
                                          "missing (under {3}'s properties."
                                          "{1}). "
                                          "Required parameters are: {2}"
                                          .format(k, hint_where,
                                                  required_parameters,
                                                  self.__class__.WHAT))


class BaseControllerNova(BaseController):
    def __init__(self, connector):
        BaseController.__init__(self)
        self.nova_client = connector.get_nova_client()


class BaseControllerNeutron(BaseController):
    def __init__(self, connector):
        BaseController.__init__(self)
        self.neutron_client = connector.get_neutron_client()


class OpenStackNetworkController(BaseControllerNeutron):
    WHAT = 'network'

    def list_objects_with_name(self, name):
        return self.neutron_client.list_networks(name=name)['networks']

    def create(self, name, ext=False):
        n = {
            'network': {
                'name': name,
                'admin_state_up': True,
            }
        }
        if ext:
            n['router:external'] = ext
        ret = self.neutron_client.create_network(n)
        return ret['network']['id']

    def get_by_id(self, id):
        return self.neutron_client.show_network(id)

    def check_for_delete_conflicts(self, network_id, **kwargs):
        # checking for collisions with unknown subnets
        # Notes:
        # 1) No check for unknown servers on the known subnets is made,
        # as it is expected for those subnets to be go through deletion
        # before the network does. Same goes for routers and router ports
        # (also note that it's impossible to connect a network without
        # subnets can't to a router port).
        # 2) While it is possible to connect a server 'directly' to a
        # network (i.e. a subnet-less network), there's no need to check for
        # server conflicts as such a network can be deleted regardless of
        # such servers, with no effect on the servers.
        # 3) On the other hand, while Openstack does allow for network
        # deletion without deleting its subnets beforehand, this in practice
        #  also deletes the underlying subnets - and therefore we do have to
        #  check for subnet conflicts.

        subnets_for_deletion = kwargs.get('subnets_for_deletion', {})
        subnet_conflicts = [('subnet', subnet) for subnet in self.get_by_id(
            network_id)['network']['subnets'] if subnet
            not in subnets_for_deletion]
        return subnet_conflicts

    def delete(self, network_id):
        self.neutron_client.delete_network(network_id)


class OpenStackSubnetController(BaseControllerNeutron):
    WHAT = 'subnet'

    def list_objects_with_name(self, name):
        return self.neutron_client.list_subnets(name=name)['subnets']

    def create(self, name, ip_version, cidr, dns_nameservers, net_id):
        ret = self.neutron_client.create_subnet({
            'subnet': {
                'name': name,
                'ip_version': ip_version,
                'cidr': cidr,
                'dns_nameservers': dns_nameservers,
                'network_id': net_id
            }
        })
        return ret['subnet']['id']

    def get_by_id(self, id):
        return self.neutron_client.show_subnet(id)

    def check_for_delete_conflicts(self, subnet_id, **kwargs):
        # checking for collisions with unknown servers and routers
        servers_for_deletion = kwargs.get('servers_for_deletion', {})
        routers_for_deletion = kwargs.get('routers_for_deletion', {})

        router_conflicts = []
        server_conflicts = []
        ports = self.neutron_client.list_ports()['ports']
        for port in ports:
            # for each port, check if it has an ip on the given subnet,
            # if it belongs to a server or a router (and not, for example,
            # a DHCP port), and if that device is up for deletion or not
            if 'device_owner' in port and \
                len(port['fixed_ips']) > 0 and \
                ((port['device_owner'] == 'network:router_interface' and
                  port['device_id'] not in routers_for_deletion) or
                 (port['device_owner'].startswith('compute') and
                  port['device_id'] not in servers_for_deletion)):
                for fixed_ip in port['fixed_ips']:
                    # should be only one, but iterating over it anyway.
                    if 'subnet_id' in fixed_ip and fixed_ip['subnet_id'] == \
                            subnet_id:
                        if port['device_owner'] == 'network:router_interface':
                            router_conflicts.append(('router',
                                                     port['device_id']))
                        else:
                            server_conflicts.append(('server',
                                                    port['device_id']))
        return server_conflicts + router_conflicts

    def delete(self, subnet_id):
        self.neutron_client.delete_subnet(subnet_id)


class OpenStackFloatingIpController(BaseControllerNeutron):
    WHAT = 'floating_ip'

    def list_objects_with_name(self, name):
        raise RuntimeError('UNSUPPORTED OPERATION')

    def create(self, name):
        raise RuntimeError('UNSUPPORTED OPERATION')

    def allocate_ip(self, external_network_id):
        floating_ip = self.neutron_client.create_floatingip(
            {
                "floatingip":
                {
                    "floating_network_id": external_network_id,
                }
            })
        return floating_ip

    def get_by_id(self, id):
        return self.neutron_client.show_floatingip(id)

    def check_for_delete_conflicts(self, floating_ip_id, **kwargs):
        return []

    def delete(self, floating_ip_id):
        self.neutron_client.delete_floatingip(floating_ip_id)


class OpenStackRouterController(BaseControllerNeutron):
    WHAT = 'router'

    def list_objects_with_name(self, name):
        return self.neutron_client.list_routers(name=name)['routers']

    def create(self, name, interfaces=None, external_gateway_info=None):
        args = {
            'router': {
                'name': name,
                'admin_state_up': True
            }
        }
        if external_gateway_info:
            args['router']['external_gateway_info'] = external_gateway_info
        router_id = self.neutron_client.create_router(args)['router']['id']
        if interfaces:
            for i in interfaces:
                self.neutron_client.add_interface_router(router_id, i)
        return router_id

    def get_by_id(self, id):
        return self.neutron_client.show_router(id)

    def check_for_delete_conflicts(self, router_id, **kwargs):
        # checking for collisions with unknown floating_ips.
        floating_ips_for_deletion = kwargs.get('floating_ips_for_deletion', {})
        floating_ips_conflicts = [('floating_ip', floating_ip['id']) for
                                  floating_ip in
                                  self.neutron_client.list_floatingips()[
                                      'floatingips'] if floating_ip[
                                      'router_id'] == router_id and
                                  floating_ip['id'] not in
                                  floating_ips_for_deletion]
        return floating_ips_conflicts

    def delete(self, router_id):
        for port in self.neutron_client.list_ports(
                device_id=router_id)['ports']:
            for interface in port['fixed_ips']:
                # should be only one, but iterating over it anyway.
                self.neutron_client.remove_interface_router(router_id,
                                                            interface)
        self.neutron_client.delete_router(router_id)


class OpenStackNovaSecurityGroupController(BaseControllerNova):
    WHAT = 'nova security group'

    def list_objects_with_name(self, name):
        sgs = self.nova_client.security_groups.list()
        return [{'id': sg.id} for sg in sgs if sg.name == name]

    def create(self, name, description, rules):
        sg = self.nova_client.security_groups.create(name, description)
        for rule in rules:
            self.nova_client.security_group_rules.create(
                sg.id,
                ip_protocol="tcp",
                from_port=rule['port'],
                to_port=rule['port'],
                cidr=rule.get('cidr'),
                group_id=rule.get('group_id')
            )
        return sg.id

    def get_by_id(self, id):
        return self.nova_client.security_groups.get(id)

    def check_for_delete_conflicts(self, sg_id, **kwargs):
        # checking for collisions with unknown servers
        servers_for_deletion = kwargs.get('servers_for_deletion', {})
        servers = self.nova_client.servers.list()
        server_conflicts = []
        for server in servers:
            if server.id not in servers_for_deletion:
                for sg in server.security_groups:
                    if sg['id'] == sg_id:
                        server_conflicts.append(('server', server.id))
        return server_conflicts

    def delete(self, sg_id):
        self.nova_client.security_groups.delete(sg_id)


class OpenStackNeutronSecurityGroupController(BaseControllerNeutron):
    WHAT = 'neutron security group'

    def list_objects_with_name(self, name):
        return self.neutron_client.list_security_groups(
            name=name)['security_groups']

    def create(self, name, description, rules):
        sg = self.neutron_client.create_security_group({
            'security_group': {
                'name': name,
                'description': description,
            }
        })['security_group']
        self.add_rules(sg['id'], rules)
        return sg['id']

    def add_rules(self, sg_id, rules):
        for rule in rules:
            self.neutron_client.create_security_group_rule({
                'security_group_rule': {
                    'security_group_id': sg_id,
                    'direction': 'ingress',
                    'protocol': 'tcp',
                    'port_range_min': rule['port'],
                    'port_range_max': rule['port'],
                    'remote_ip_prefix': rule.get('cidr'),
                    'remote_group_id': rule.get('group_id'),
                }
            })

    def get_by_id(self, id):
        return self.neutron_client.show_security_group(id)

    def check_for_delete_conflicts(self, sg_id, **kwargs):
        # checking for collisions with unknown servers and routers.
        # note that there's no 'routers_for_deletion' parameter, as we don't
        # link between any security group and a router port on bootstrap,
        # so any linked port is in fact a conflict.
        servers_for_deletion = kwargs.get('servers_for_deletion', {})
        server_conflicts = []
        router_conflicts = []
        for port in self.neutron_client.list_ports()['ports']:
            if sg_id in port['security_groups']:
                if port['device_owner'] == 'network:router_interface':
                    router_conflicts.append(('router', port['device_id']))
                elif port['device_owner'].startswith('compute') and \
                        port['device_id'] not in servers_for_deletion:
                    server_conflicts.append(('server', port['device_id']))
        return server_conflicts + router_conflicts

    def delete(self, sg_id):
        self.neutron_client.delete_security_group(sg_id)


class OpenStackKeypairController(BaseControllerNova):
    WHAT = 'keypair'

    def list_objects_with_name(self, name):
        keypairs = self.nova_client.keypairs.list()
        return [{'id': keypair.id} for keypair in keypairs if
                keypair.id == name]

    def create(self, key_name, private_key_target_path=None,
               public_key_filepath=None, *args, **kwargs):
        if not private_key_target_path and not public_key_filepath:
            raise RuntimeError("Must provide either private key target path "
                               "or public key filepath to create keypair")

        if public_key_filepath:
            with open(expanduser(public_key_filepath), 'r') as f:
                keypair = self.nova_client.keypairs.create(key_name, f.read())
        else:
            keypair = self.nova_client.keypairs.create(key_name)
            pk_target_path = expanduser(private_key_target_path)
            self._mkdir_p(os.path.dirname(private_key_target_path))
            with open(pk_target_path, 'w') as f:
                f.write(keypair.private_key)
                os.system('chmod 600 {0}'.format(pk_target_path))
        return keypair.id

    def get_by_id(self, id):
        return self.nova_client.keypairs.get(id)

    def _mkdir_p(self, path):
        path = expanduser(path)
        try:
            lgr.debug('creating dir {0}'.format(path))
            os.makedirs(path)
        except OSError, exc:
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                return
            raise

    def check_for_delete_conflicts(self, keypair_id, **kwargs):
        # Note: While it might be somewhat weird to delete a keypair which is
        # currently in use by a server, Openstack does allow this and thus
        # so do we.
        return []

    def delete(self, keypair_id):
        self.nova_client.keypairs.delete(keypair_id)


class OpenStackServerController(BaseControllerNova):
    WHAT = 'server'

    def list_objects_with_name(self, name):
        name_re = '^' + re.escape(name) + '$'
        servers = self.nova_client.servers.list(True, {'name': name_re})
        return [{'id': server.id} for server in servers]

    def create(self, name, server_config, management_server_keypair_name,
               sgm_id, creation_timeout, *args, **kwargs):
        """
        Creates a server. Exposes the parameters mentioned in
        http://docs.openstack.org/developer/python-novaclient/api/novaclient
        .v1_1.servers.html#novaclient.v1_1.servers.ServerManager.create
        """

        self._fail_on_missing_required_parameters(
            server_config,
            ('name', 'flavor', 'image'),
            'compute.management_server.instance')

        # First parameter is 'self', skipping
        params_names = inspect.getargspec(
            self.nova_client.servers.create).args[1:]
        params_default_values = inspect.getargspec(
            self.nova_client.servers.create).defaults
        params = dict(itertools.izip(params_names, params_default_values))

        # Fail on unsupported parameters
        for k in server_config:
            if k not in params:
                raise ValueError("Parameter with name '{0}' must not be passed"
                                 " to openstack provisioner (under "
                                 "compute.management_server.instance)"
                                 .format(k))

        for k in params:
            if k in server_config:
                params[k] = server_config[k]

        server_name = server_config['name']
        if self.find_by_name(server_name):
            raise RuntimeError("Can not provision the server with name '{0}'"
                               " because server with such name "
                               "already exists"
                               .format(server_name))

        lgr.debug("Asking Nova to create server. Parameters: {0}"
                  .format(str(params)))

        configured_sgs = []
        if params['security_groups'] is not None:
            configured_sgs = params['security_groups']
        params['security_groups'] = [sgm_id] + configured_sgs

        params['key_name'] = management_server_keypair_name

        server = self.nova_client.servers.create(**params)
        server = self._wait_for_server_to_become_active(server_name, server,
                                                        creation_timeout)
        return server.id

    def add_floating_ip(self, server_id, ip):

        # Extra: detach floating ip from existng server
        while True:
            ls = self.nova_client.floating_ips.findall(ip=ip)
            if len(ls) == 0:
                raise OpenStackLogicError(
                    "Floating IP {0} does not exist so it can "
                    "not be attached to server {1}".format(ip, server_id))
            if len(ls) > 1:
                raise OpenStackLogicError(
                    "Floating IP {0} is attached to "
                    "{1} instances".format(ip, len(ls)))

            if not ls[0].instance_id:
                lgr.debug(
                    "Floating IP {0} is not attached to any instance. "
                    "Continuing.".format(ip))
                break

            lgr.debug(
                "Floating IP {0} is attached "
                "to instance {1}. Detaching.".format(ip, ls[0].instance_id))
            self.nova_client.servers.remove_floating_ip(ls[0].instance_id, ip)
            time.sleep(1)

        server = self.nova_client.servers.get(server_id)
        server.add_floating_ip(ip)

    def get_server_ips_in_network(self, server_id, network_name):
        server = self.nova_client.servers.get(server_id)
        if network_name not in server.networks:
            raise OpenStackLogicError(
                "Server {0} ({1}) does not have address in"
                " network {2}".format(server.name, server_id, network_name))
        return server.networks[network_name]

    def _wait_for_server_to_become_active(self, server_name, server,
                                          creation_timeout):
        while server.status != "ACTIVE":
            creation_timeout -= 5
            if creation_timeout <= 0:
                raise RuntimeError('Server failed to start in time (creation '
                                   'timeout was {} seconds)'
                                   .format(creation_timeout))
            time.sleep(5)
            server = self.nova_client.servers.get(server.id)

        return server

    def get_by_id(self, id):
        return self.nova_client.servers.get(id)

    def check_for_delete_conflicts(self, server_id, **kwargs):
        return []

    def delete(self, server_id):
        self.nova_client.servers.delete(server_id)


class OpenStackConnector(object):
    # TODO: maybe lazy?
    def __init__(self, provider_config):
        self.config = provider_config
        self.keystone_client = keystone_client.Client(
            **self.config['keystone'])

        if self.config['networking']['neutron_supported_region']:

            # if neutron not explicitly specified, use catalog to locate
            # public URL of 'network' service
            self._modify_neutron_url_from_catalog()

            self.neutron_client = \
                neutron_client.Client('2.0',
                                      endpoint_url=provider_config
                                      ['networking']
                                      ['neutron_url'],
                                      token=self.keystone_client.auth_token)
            self.neutron_client.format = 'json'
        else:
            self.neutron_client = None

        kconf = self.config['keystone']
        self.nova_client = nova_client.Client(
            kconf['username'],
            kconf['password'],
            kconf['tenant_name'],
            kconf['auth_url'],
            region_name=self.config['compute']['region'],
            http_log_debug=False
        )

    def _modify_neutron_url_from_catalog(self):
        """
        If neutron URL is not set or is empty, use the public URL
        """
        neutron_url = None
        if self.config['networking'].get('neutron_url', '') == '':
            # neutron service names differ in some installations
            neutron_service_names = ['network', 'neutron']
            region = self.config['compute']['region']

            for service_name in neutron_service_names:
                neutron_url = \
                    self.keystone_client.service_catalog.url_for(
                        service_type=service_name, endpoint_type='publicURL',
                        region_name=region)

                if neutron_url is not None:
                    break

        if neutron_url is not None:
            self.config['networking']['neutron_url'] = neutron_url

    def get_keystone_client(self):
        return self.keystone_client

    def get_neutron_client(self):
        return self.neutron_client

    def get_nova_client(self):
        return self.nova_client
