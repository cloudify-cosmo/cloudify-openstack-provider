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
import shutil
import inspect
import itertools
import time
import yaml
import json
import socket
import paramiko
import tempfile
import sys
from os.path import expanduser
from copy import deepcopy
from scp import SCPClient
from fabric.api import run, env
from fabric.context_managers import settings, hide
import logging
import logging.config
import config

# Validator
from IPy import IP
from jsonschema import ValidationError, Draft4Validator
from schemas import OPENSTACK_SCHEMA

# OpenStack
import keystoneclient.v2_0.client as keystone_client
import novaclient.v1_1.client as nova_client
import neutronclient.neutron.client as neutron_client


EP_FLAG = 'use_existing'

EXTERNAL_MGMT_PORTS = (22, 8100)  # SSH, REST service
INTERNAL_MGMT_PORTS = (5555, 5672, 53229)  # Riemann, RabbitMQ, FileServer

INTERNAL_AGENT_PORTS = (22,)

SSH_CONNECT_RETRIES = 12
SSH_CONNECT_SLEEP = 5
SSH_CONNECT_PORT = 22

SHELL_PIPE_TO_LOGGER = ' |& logger -i -t cosmo-bootstrap -p local0.info'

FABRIC_RETRIES = 3
FABRIC_SLEEPTIME = 3

CONFIG_FILE_NAME = 'cloudify-config.yaml'
DEFAULTS_CONFIG_FILE_NAME = 'cloudify-config.defaults.yaml'

CLOUDIFY_PACKAGES_PATH = '/cloudify'
CLOUDIFY_COMPONENTS_PACKAGE_PATH = '/cloudify-components'
CLOUDIFY_CORE_PACKAGE_PATH = '/cloudify-core'
CLOUDIFY_UI_PACKAGE_PATH = '/cloudify-ui'
CLOUDIFY_AGENT_PACKAGE_PATH = '/cloudify-agents'

verbose_output = False


# initialize logger
if os.path.isfile(config.LOG_DIR):
    sys.exit('file {0} exists - cloudify log directory cannot be created '
             'there. please remove the file and try again.'
             .format(config.LOG_DIR))
try:
    logfile = config.LOGGER['handlers']['file']['filename']
    d = os.path.dirname(logfile)
    if not os.path.exists(d):
        os.makedirs(d)
    logging.config.dictConfig(config.LOGGER)
    lgr = logging.getLogger('main')
    lgr.setLevel(logging.INFO)
    flgr = logging.getLogger('file')
    flgr.setLevel(logging.DEBUG)
except ValueError:
    sys.exit('could not initialize logger.'
             ' verify your logger config'
             ' and permissions to write to {0}'
             .format(logfile))

# http://stackoverflow.com/questions/8144545/turning-off-logging-in-paramiko
logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.getLogger("requests.packages.urllib3.connectionpool").setLevel(
    logging.ERROR)


def init(target_directory, reset_config, is_verbose_output=False):
    _set_global_verbosity_level(is_verbose_output)

    if not reset_config and os.path.exists(
            os.path.join(target_directory, CONFIG_FILE_NAME)):
        return False

    provider_dir = os.path.dirname(os.path.realpath(__file__))
    files_path = os.path.join(provider_dir, CONFIG_FILE_NAME)

    lgr.debug('copying provider files from {0} to {1}'
              .format(files_path, target_directory))
    shutil.copy(files_path, target_directory)
    return True


def bootstrap(config_path=None, is_verbose_output=False,
              bootstrap_using_script=True, keep_up=False,
              dev_mode=False):
    driver = _get_driver(config_path, is_verbose_output=is_verbose_output)
    mgmt_ip, provider_context = \
        driver.bootstrap(bootstrap_using_script, keep_up, dev_mode)
    return mgmt_ip, provider_context


def teardown(provider_context, ignore_validation=False, config_path=None,
             is_verbose_output=False):
    driver = _get_driver(config_path, provider_context, is_verbose_output)
    driver.delete_topology(ignore_validation)


def _get_driver(config_path, provider_context=None, is_verbose_output=False):
    _set_global_verbosity_level(is_verbose_output)
    provider_config = _read_config(config_path)
    provider_context = provider_context if provider_context else {}
    _validate_config(provider_config)
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


def _set_global_verbosity_level(is_verbose_output=False):
    # we need both lgr.setLevel and the verbose_output parameter
    # since not all output is generated at the logger level.
    # verbose_output can help us control that.
    global verbose_output
    verbose_output = is_verbose_output
    if verbose_output:
        lgr.setLevel(logging.DEBUG)


def _read_config(config_file_path):

    if not config_file_path:
        config_file_path = CONFIG_FILE_NAME
    defaults_config_file_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        DEFAULTS_CONFIG_FILE_NAME)

    if not os.path.exists(config_file_path) or not os.path.exists(
            defaults_config_file_path):
        if not os.path.exists(defaults_config_file_path):
            raise ValueError('Missing the defaults configuration file; '
                             'expected to find it at {0}'.format(
                                 defaults_config_file_path))
        raise ValueError('Missing the configuration file; expected to find '
                         'it at {0}'.format(config_file_path))

    lgr.debug('reading provider config files')
    with open(config_file_path, 'r') as config_file, \
            open(defaults_config_file_path, 'r') as defaults_config_file:

        lgr.debug('safe loading user config')
        user_config = yaml.safe_load(config_file.read())

        lgr.debug('safe loading default config')
        defaults_config = yaml.safe_load(defaults_config_file.read())

    lgr.debug('merging configs')
    merged_config = _deep_merge_dictionaries(user_config, defaults_config) \
        if user_config else defaults_config
    return merged_config


def _deep_merge_dictionaries(overriding_dict, overridden_dict):
    merged_dict = deepcopy(overridden_dict)
    for k, v in overriding_dict.iteritems():
        if k in merged_dict and isinstance(v, dict):
            if isinstance(merged_dict[k], dict):
                merged_dict[k] = _deep_merge_dictionaries(v, merged_dict[k])
            else:
                raise RuntimeError('type conflict at key {0}'.format(k))
        else:
            merged_dict[k] = deepcopy(v)
    return merged_dict


def _mkdir_p(path):
    try:
        lgr.debug('creating dir {0}'
                  .format(path))
        os.makedirs(path)
    except OSError, exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            return
        raise


def _validate_config(provider_config, schema=OPENSTACK_SCHEMA):
    global validated
    validated = True
    verifier = OpenStackConfigFileValidator()

    lgr.info('validating provider configuration file...')
    verifier._validate_cidr('networking.subnet.cidr',
                            provider_config['networking']
                            ['subnet']['cidr'])
    verifier._validate_cidr('networking.management_security_group.cidr',
                            provider_config['networking']
                            ['management_security_group']['cidr'])
    verifier._validate_schema(provider_config, schema)

    if validated:
        lgr.info('provider configuration file validated successfully')
    else:
        lgr.error('provider configuration validation failed!')
        sys.exit(1)


def _format_resource_name(res_type, res_id, res_name=None):
    if res_name:
        return "{0} - {1} - {2}".format(res_type, res_id, res_name)
    else:
        return "{0} - {1}".format(res_type, res_id)


class OpenStackConfigFileValidator:

    def _validate_schema(self, provider_config, schema):
        global validated
        v = Draft4Validator(schema)
        if v.iter_errors(provider_config):
            errors = ';\n'.join('config file validation error found at key:'
                                ' %s, %s' % ('.'.join(e.path), e.message)
                                for e in v.iter_errors(provider_config))
        try:
            v.validate(provider_config)
        except ValidationError:
            validated = False
            lgr.error('{0}'.format(errors))

    def _validate_cidr(self, field, cidr):
        global validated
        try:
            IP(cidr)
        except ValueError as e:
            validated = False
            lgr.error('config file validation error found at key:'
                      ' {0}. {1}'.format(field, e.message))


class CosmoOnOpenStackDriver(object):
    """ Bootstraps Cosmo on OpenStack """

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

    def bootstrap(self, bootstrap_using_script, keep_up, dev_mode):

        installed = None
        mgmt_ip, private_ip = self.create_topology()

        if mgmt_ip is not None:
            installed = self._bootstrap_manager(mgmt_ip,
                                                private_ip,
                                                bootstrap_using_script,
                                                dev_mode)

        if mgmt_ip and installed:
            return mgmt_ip, self.provider_context
        else:
            if keep_up:
                lgr.info('topology will remain up')
                sys.exit(1)
            else:
                lgr.info('tearing down topology'
                         ' due to bootstrap failure')
                self.delete_topology()
                sys.exit(1)

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
                {k: v for k, v in insconf.iteritems() if k != EP_FLAG},
                mgr_kpconf['name'],
                msg_id if is_neutron_supported_region else msgconf['name']
            )

        if is_neutron_supported_region:
            network_name = nconf['name']
            if not insconf[EP_FLAG]:  # new server
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
        return public_ip, private_ip

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

    def _get_private_key_path_from_keypair_config(self, keypair_config):
        path = keypair_config['provided']['private_key_filepath'] if \
            'provided' in keypair_config else \
            keypair_config['auto_generated']['private_key_target_path']
        return expanduser(path)

    def _run_with_retries(self, command, retries=FABRIC_RETRIES,
                          sleeper=FABRIC_SLEEPTIME):

        for execution in range(retries):
            lgr.debug('running command: {0}'
                      .format(command))
            if not self.verbose_output:
                with hide('running', 'stdout'):
                    r = run(command)
            else:
                r = run(command)
            if r.succeeded:
                lgr.debug('successfully ran command: {0}'
                          .format(command))
                return True
            else:
                lgr.warning('retrying command: {0}'
                            .format(command))
                time.sleep(sleeper)
        lgr.error('failed to run: {0}, {1}'
                  .format(command, r.stderr))
        return False

    def _download_package(self, url, path):
        return self._run_with_retries('sudo wget {0} -P {1}'
                                      .format(path, url))

    def _unpack(self, path):
        return self._run_with_retries('sudo dpkg -i {0}/*.deb'.format(path))

    def _run(self, command):
        return self._run_with_retries(command)

    def _bootstrap_manager(self,
                           mgmt_ip,
                           private_ip,
                           bootstrap_using_script,
                           dev_mode):
        lgr.info('initializing manager on the machine at {0}'
                 .format(mgmt_ip))
        compute_config = self.config['compute']
        cosmo_config = self.config['cloudify']
        mgmt_server_config = compute_config['management_server']
        mgr_kpconf = compute_config['management_server']['management_keypair']

        lgr.debug('creating ssh channel to machine...')
        try:
            ssh = self._create_ssh_channel_with_mgmt(
                mgmt_ip,
                self._get_private_key_path_from_keypair_config(
                    mgmt_server_config['management_keypair']),
                mgmt_server_config['user_on_management'])
        except:
            lgr.info('ssh channel creation failed. '
                     'your private and public keys might not be matching or '
                     'your security group might not be configured to allow '
                     'connections to port {0}.'.format(SSH_CONNECT_PORT))
            return False

        env.user = mgmt_server_config['user_on_management']
        env.warn_only = True
        env.abort_on_prompts = False
        env.connection_attempts = 5
        env.keepalive = 0
        env.linewise = False
        env.pool_size = 0
        env.skip_bad_hosts = False
        env.timeout = 10
        env.forward_agent = True
        env.status = False
        env.key_filename = [mgr_kpconf['auto_generated']
                            ['private_key_target_path']]

        if not bootstrap_using_script:
            try:
                self._copy_files_to_manager(
                    ssh,
                    mgmt_server_config['userhome_on_management'],
                    self.config['keystone'],
                    self._get_private_key_path_from_keypair_config(
                        compute_config['agent_servers']['agents_keypair']),
                    self.config['networking'])
            except:
                lgr.error('failed to copy keystone files')
                return False

            with settings(host_string=mgmt_ip), hide('running',
                                                     'stderr',
                                                     'aborts',
                                                     'warnings'):

                lgr.info('downloading cloudify-components package...')
                r = self._download_package(
                    CLOUDIFY_PACKAGES_PATH,
                    cosmo_config['cloudify_components_package_url'])
                if not r:
                    lgr.error('failed to download components package. '
                              'please ensure package exists in its '
                              'configured location in the config file')
                    return False

                lgr.info('downloading cloudify-core package...')
                r = self._download_package(
                    CLOUDIFY_PACKAGES_PATH,
                    cosmo_config['cloudify_package_url'])
                if not r:
                    lgr.error('failed to download core package. '
                              'please ensure package exists in its '
                              'configured location in the config file')
                    return False

                lgr.info('downloading cloudify-ui...')
                r = self._download_package(
                    CLOUDIFY_UI_PACKAGE_PATH,
                    cosmo_config['cloudify_ui_package_url'])
                if not r:
                    lgr.error('failed to download ui package. '
                              'please ensure package exists in its '
                              'configured location in the config file')
                    return False

                lgr.info('downloading cloudify-ubuntu-agent...')
                r = self._download_package(
                    CLOUDIFY_AGENT_PACKAGE_PATH,
                    cosmo_config['cloudify_ubuntu_agent_url'])
                if not r:
                    lgr.error('failed to download ubuntu agent. '
                              'please ensure package exists in its '
                              'configured location in the config file')
                    return False

                lgr.info('unpacking cloudify-core packages...')
                r = self._unpack(
                    CLOUDIFY_PACKAGES_PATH)
                if not r:
                    lgr.error('failed to unpack cloudify-core package')
                    return False

                lgr.debug('verifying verbosity for installation process')
                v = self.verbose_output
                self.verbose_output = True

                lgr.info('installing cloudify on {0}...'.format(mgmt_ip))
                r = self._run('sudo {0}/cloudify-components-bootstrap.sh'
                              .format(CLOUDIFY_COMPONENTS_PACKAGE_PATH))
                if not r:
                    lgr.error('failed to install cloudify-components')
                    return False

                celery_user = mgmt_server_config['user_on_management']
                r = self._run('sudo {0}/cloudify-core-bootstrap.sh {1} {2}'
                              .format(CLOUDIFY_CORE_PACKAGE_PATH,
                                      celery_user, private_ip))
                if not r:
                    lgr.error('failed to install cloudify-core')
                    return False

                lgr.info('deploying cloudify-ui')
                self.verbose_output = False
                r = self._unpack(
                    CLOUDIFY_UI_PACKAGE_PATH)
                if not r:
                    lgr.error('failed to install cloudify-ui')
                    return False
                lgr.info('done')

                lgr.info('deploying cloudify-ubuntu-agent')
                self.verbose_output = False
                r = self._unpack(
                    CLOUDIFY_AGENT_PACKAGE_PATH)
                if not r:
                    lgr.error('failed to install cloudify-ubuntu-agent')
                    return False
                lgr.info('done')

                self.verbose_output = True
                if dev_mode:
                    lgr.info('\n\n\n\n\nentering dev-mode. '
                             'dev configuration will be applied...\n'
                             'NOTE: an internet connection might be '
                             'required...')

                    dev_config = self.config['dev']
                    # lgr.debug(json.dumps(dev_config, sort_keys=True,
                    #           indent=4, separators=(',', ': ')))

                    for key, value in dev_config.iteritems():
                        virtualenv = value['virtualenv']
                        lgr.debug('virtualenv is: ' + str(virtualenv))

                        if 'preruns' in value:
                            for command in value['preruns']:
                                self._run(command)

                        if 'downloads' in value:
                            self._run('mkdir -p /tmp/{0}'.format(virtualenv))
                            for download in value['downloads']:
                                lgr.debug('downloading: ' + download)
                                self._run('sudo wget {0} -O '
                                          '/tmp/module.tar.gz'
                                          .format(download))
                                self._run('sudo tar -C /tmp/{0} -xvf {1}'
                                          .format(virtualenv,
                                                  '/tmp/module.tar.gz'))

                        if 'installs' in value:
                            for module in value['installs']:
                                lgr.debug('installing: ' + module)
                                if module.startswith('/'):
                                    module = '/tmp' + virtualenv + module
                                self._run('sudo {0}/bin/pip '
                                          '--default-timeout'
                                          '=45 install {1} --upgrade'
                                          ' --process-dependency-links'
                                          .format(virtualenv, module))
                        if 'runs' in value:
                            for command in value['runs']:
                                self._run(command)

                    lgr.info('managenet ip is {0}'.format(mgmt_ip))
                lgr.debug('setting verbosity to previous state')
                self.verbose_output = v
                return True
        else:
            try:
                self._copy_files_to_manager(
                    ssh,
                    mgmt_server_config['userhome_on_management'],
                    self.config['keystone'],
                    self._get_private_key_path_from_keypair_config(
                        compute_config['agent_servers']['agents_keypair']),
                    self.config['networking'])

                lgr.debug('Installing required packages'
                          ' on manager')
                self._exec_command_on_manager(ssh, 'echo "127.0.0.1 '
                                                   '$(cat /etc/hostname)" | '
                                                   'sudo tee -a /etc/hosts')
                # note we call 'apt-get update' twice. there seems to be
                # an issue an certain openstack environments where the first
                # call seems to be using a different set of servers to do the
                # update. the second calls seems to be after a certain
                # mysterious cache was invalidated.
                self._exec_command_on_manager(ssh, 'sudo apt-get -y -q update'
                                                   + SHELL_PIPE_TO_LOGGER)
                self._exec_command_on_manager(ssh, 'sudo apt-get -y -q update'
                                                   + SHELL_PIPE_TO_LOGGER)
                self._exec_install_command_on_manager(ssh,
                                                      'apt-get install -y -q '
                                                      'python-dev git rsync '
                                                      'openjdk-7-jdk maven '
                                                      'python-pip'
                                                      + SHELL_PIPE_TO_LOGGER)
                self._exec_install_command_on_manager(ssh, 'pip install -q '
                                                           'retrying requests '
                                                           'timeout-decorator')

                # use open sdk java 7
                self._exec_command_on_manager(
                    ssh,
                    'sudo update-alternatives --set java '
                    '/usr/lib/jvm/java-7-openjdk-amd64/jre/bin/java')

                # configure and clone cosmo-manager from github
                branch = cosmo_config['cloudify_branch']
                workingdir = '{0}/cosmo-work'.format(
                    mgmt_server_config['userhome_on_management'])
                version = cosmo_config['cloudify_branch']
                configdir = '{0}/cosmo-manager/vagrant'.format(workingdir)

                lgr.debug('cloning cosmo on manager')
                self._exec_command_on_manager(ssh, 'mkdir -p {0}'
                                              .format(workingdir))
                self._exec_command_on_manager(ssh,
                                              'git clone https://github.com/'
                                              'CloudifySource/cosmo-manager'
                                              '.git {0}/cosmo-manager'
                                              ' --depth 1'
                                              .format(workingdir))
                self._exec_command_on_manager(ssh, '( cd {0}/cosmo-manager ; '
                                                   'git checkout {1} )'
                                                   .format(workingdir, branch))

                lgr.debug('running the manager bootstrap script '
                          'remotely')
                run_script_command = 'DEBIAN_FRONTEND=noninteractive ' \
                                     'python2.7 {0}/cosmo-manager/vagrant/' \
                                     'bootstrap_lxc_manager.py ' \
                                     '--working_dir={0} --cosmo_version={1} ' \
                                     '--config_dir={2} ' \
                                     '--install_openstack_provisioner ' \
                                     '--install_logstash ' \
                                     '--management_ip={3}' \
                                     .format(workingdir,
                                             version,
                                             configdir,
                                             private_ip)
                run_script_command += ' {0}'.format(SHELL_PIPE_TO_LOGGER)
                self._exec_command_on_manager(ssh, run_script_command)

                lgr.debug('rebuilding cosmo on manager')
            except:
                lgr.error('failed to install manager using the script')
                return False
            finally:
                ssh.close()
            return True

    def _create_ssh_channel_with_mgmt(self, mgmt_ip, management_key_path,
                                      user_on_management):
        ssh = paramiko.SSHClient()
        # TODO: support fingerprint in config json
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # trying to ssh connect to management server. Using retries since it
        # might take some time to find routes to host
        for retry in range(0, SSH_CONNECT_RETRIES):
            try:
                ssh.connect(mgmt_ip, username=user_on_management,
                            key_filename=management_key_path,
                            look_for_keys=False, timeout=10)
                lgr.debug('ssh connection successful')
                return ssh
            except socket.error as err:
                lgr.debug(
                    "SSH connection to {0} failed ({1}). Waiting {2} seconds "
                    "before retrying".format(mgmt_ip, err, 5))
                time.sleep(5)
        lgr.error('Failed to ssh connect to management server ({0}'
                  .format(err))

    def _copy_files_to_manager(self, ssh, userhome_on_management,
                               keystone_config, agents_key_path,
                               networking):
        lgr.info('uploading keystone and neutron files to manager')
        scp = SCPClient(ssh.get_transport())

        tempdir = tempfile.mkdtemp()
        try:
            scp.put(agents_key_path, userhome_on_management + '/.ssh',
                    preserve_times=True)
            keystone_file_path = self._make_keystone_file(tempdir,
                                                          keystone_config)
            scp.put(keystone_file_path, userhome_on_management,
                    preserve_times=True)
            if networking['neutron_supported_region']:
                neutron_file_path = self._make_neutron_file(tempdir,
                                                            networking)
                scp.put(neutron_file_path, userhome_on_management,
                        preserve_times=True)
        finally:
            shutil.rmtree(tempdir)

    def _make_keystone_file(self, tempdir, keystone_config):
        # put default region in keystone_config file
        keystone_config['region'] = self.config['compute']['region']
        keystone_file_path = os.path.join(tempdir, 'keystone_config.json')
        with open(keystone_file_path, 'w') as f:
            json.dump(keystone_config, f)
        return keystone_file_path

    def _make_neutron_file(self, tempdir, networking):
        neutron_file_path = os.path.join(tempdir, 'neutron_config.json')
        with open(neutron_file_path, 'w') as f:
            json.dump({'url': networking['neutron_url']}, f)
        return neutron_file_path

    def _exec_install_command_on_manager(self, ssh, install_command):
        command = 'DEBIAN_FRONTEND=noninteractive sudo -E {0}'.format(
            install_command)
        return self._exec_command_on_manager(ssh, command)

    def _exec_command_on_manager(self, ssh, command):
        lgr.info('EXEC START: {0}'.format(command))
        chan = ssh.get_transport().open_session()
        chan.exec_command(command)
        stdin = chan.makefile('wb', -1)
        stdout = chan.makefile('rb', -1)
        stderr = chan.makefile_stderr('rb', -1)

        try:
            exit_code = chan.recv_exit_status()
            if exit_code != 0:
                errors = stderr.readlines()
                raise RuntimeError('Error occurred when trying to run a '
                                   'command on the management machine. '
                                   'command was: {0} ; Error(s): {1}'
                                   .format(command, errors))

            response_lines = stdout.readlines()
            lgr.info('EXEC END: {0}'.format(command))
            return response_lines
        finally:
            stdin.close()
            stdout.close()
            stderr.close()
            chan.close()


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
        if return_created:
            return id, created
        else:
            return id

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
            if use_existing:
                raise is configured to use_existing but does not exist
            create resource
        """
        if self._check(name, *args, **kw):
            if self.__class__.WHAT in ('server'):
                raise OpenStackLogicError("{0} '{1}' already exists".format(
                                          self.__class__.WHAT, name))
            the_id = self.ensure_exists(name, *args, **kw)
            created = False
        else:
            if EP_FLAG in provider_config and provider_config[EP_FLAG]:
                raise OpenStackLogicError("{0} '{1}' is configured to 'use_"
                                          "existing' but does not exist"
                                          .format(self.__class__.WHAT, name))
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
            with open(public_key_filepath, 'r') as f:
                keypair = self.nova_client.keypairs.create(key_name, f.read())
        else:
            keypair = self.nova_client.keypairs.create(key_name)
            pk_target_path = expanduser(private_key_target_path)
            _mkdir_p(os.path.dirname(private_key_target_path))
            with open(pk_target_path, 'w') as f:
                f.write(keypair.private_key)
                os.system('chmod 600 {0}'.format(pk_target_path))
        return keypair.id

    def get_by_id(self, id):
        return self.nova_client.keypairs.get(id)

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
        servers = self.nova_client.servers.list(True, {'name': name})
        return [{'id': server.id} for server in servers]

    def create(self, name, server_config, management_server_keypair_name,
               sgm_id, *args, **kwargs):
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
        server = self._wait_for_server_to_become_active(server_name, server)
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

    def _wait_for_server_to_become_active(self, server_name, server):
        timeout = 100
        while server.status != "ACTIVE":
            timeout -= 5
            if timeout <= 0:
                raise RuntimeError('Server failed to start in time')
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

    def get_keystone_client(self):
        return self.keystone_client

    def get_neutron_client(self):
        return self.neutron_client

    def get_nova_client(self):
        return self.nova_client
