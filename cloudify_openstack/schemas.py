# flake8: NOQA
########
# Copyright (c) 2013 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.

PROVIDER_CONFIG_SCHEMA = {
    "type": "object",
    "required": [
        'keystone',
        'networking',
        'compute',
        'cloudify'
    ],
    "properties": {
        "cloudify": {
            "type": "object",
            "required": [
                'server',
                'agents',
                'workflows',
                'bootstrap'
            ],
            "properties": {
                "resources_prefix": {
                    "type": "string"
                "server": {
                    "type": "object",
                    "required": [
                        'packages',
                    ],
                    "properties": {
                        "packages": {
                            "type": "object",
                            "required": [
                                'components_package_url',
                                'core_package_url',
                            ],
                            "properties": {
                                "components_package_url": {
                                    "type": "string",
                                },
                                "core_package_url": {
                                    "type": "string",
                                },
                                "ui_package_url": {
                                    "type": "string",
                                }
                            },
                            "additionalProperties": False
                        },
                    },
                    "additionalProperties": False
                }
                "agents": {
                    "type": "object",
                    "required": [
                        'packages',
                        'config',
                    ],
                    "properties": {
                        "packages": {
                            "type": "object"
                        },
                        "config": {
                            "type": "object",
                            "required": ["min_workers", "max_workers",
                                         "remote_execution_port"],
                            "properties": {
                                "min_workers": {
                                    "type": "number"
                                },
                                "max_workers": {
                                    "type": "number"
                                },
                                "remote_execution_port": {
                                    "type": "number"
                                },
                                "user": {
                                    "type": "string"
                                }
                            },
                            "additionalProperties": False
                        },
                    "additionalProperties": False
                    }
                },
                "workflows": {
                    "type": "object",
                    "required": ["task_retries", "retry_interval"],
                    "properties": {
                        "task_retries": {
                            "type": "number"
                        },
                        "retry_interval": {
                            "type": "number"
                        }
                    },
                    "additionalProperties": False
                },
                "bootstrap": {
                    "type": "object",
                    "properties": {
                        "ssh": {
                            "type": "object",
                            "properties": {
                                "initial_connectivity_retries": {
                                    "type": "number"
                                },
                                "initial_connectivity_retries_interval": {
                                    "type": "number"
                                },
                                "command_retries": {
                                    "type": "number"
                                },
                                "retries_interval": {
                                    "type": "number"
                                },
                                "connection_attempts": {
                                    "type": "number"
                                },
                                "socket_timeout": {
                                    "type": "number"
                                }
                            },
                            "additionalProperties": False
                        }
                    },
                    "additionalProperties": False
                }
            },
            "additionalProperties": False
        },
        "compute": {
            "type": "object",
            "required": [
                'management_server',
                'agent_servers',
                'region'
            ],
            "properties": {
                "agent_servers": {
                    "type": "object",
                    "required": ["agents_keypair"],
                    "properties": {
                        "agents_keypair": {
                            "type": "object",
                            "required": ["private_key_path", "name",
                                         "create_if_missing"],
                            "properties": {
                                "private_key_path": {
                                    "type": "string",
                                },
                                "create_if_missing": {
                                    "enum": [True, False],
                                },
                                "name": {
                                    "type": "string",
                                }
                            },
                            "additionalProperties": False
                        }
                    },
                    "additionalProperties": False
                },
                "management_server": {
                    "type": "object",
                    "required": ["user_on_management",
                                 "userhome_on_management",
                                 "creation_timeout",
                                 "instance",
                                 "management_keypair"],
                    "properties": {
                        "instance": {
                            "type": "object",
                            "required": ["create_if_missing", "name",
                                         "image", "flavor"],
                            "properties": {
                                "create_if_missing": {
                                    "enum": [True, False],
                                },
                                "flavor": {
                                    "type": "number",
                                },
                                "image": {
                                    "type": ["number", "string"],
                                },
                                "name": {
                                    "type": "string",
                                }
                            },
                            "additionalProperties": False
                        },
                        "management_keypair": {
                            "type": "object",
                            "required": ["private_key_path", "name",
                                         "create_if_missing"],
                            "properties": {
                                "private_key_path": {
                                    "type": "string",
                                },
                                "create_if_missing": {
                                    "enum": [True, False],
                                },
                                "name": {
                                    "type": "string",
                                }
                            },
                            "additionalProperties": False
                        },
                        "user_on_management": {
                            "type": "string",
                        },
                        "userhome_on_management": {
                            "type": "string",
                        },
                        "creation_timeout": {
                            "type": "number",
                        },
                        "floating_ip": {
                            "type": "string"
                        }
                    },
                    "additionalProperties": False
                },
                "region": {
                    "type": "string",
                }
            },
            "additionalProperties": False
        },
        "keystone": {
            "type": "object",
            "required": ["auth_url", "password", "tenant_name", "username"],
            "properties": {
                "auth_url": {
                    "type": "string",
                },
                "password": {
                    "type": "string",
                },
                "tenant_name": {
                    "type": "string",
                },
                "username": {
                    "type": "string",
                }
            },
            'additionalProperties': False,
        },
        "networking": {
            "type": "object",
            "required": [
                "agents_security_group",
                "ext_network",
                "int_network",
                "management_security_group",
                "neutron_supported_region",
                "router",
                "subnet"
            ],
            "properties": {
                "agents_security_group": {
                    "type": "object",
                    "properties": {
                        "create_if_missing": {
                            "enum": [True, False],
                        },
                        "name": {
                            "type": "string",
                        }
                    },
                    "required": ["create_if_missing", "name"],
                    'additionalProperties': False
                },
                "ext_network": {
                    "type": "object",
                    "properties": {
                        "create_if_missing": {
                            "enum": [True, False],
                        },
                        "name": {
                            "type": "string",
                        }
                    },
                    "required": ["create_if_missing", "name"],
                    'additionalProperties': False
                },
                "int_network": {
                    "type": "object",
                    "properties": {
                        "create_if_missing": {
                            "enum": [True, False],
                        },
                        "name": {
                            "type": "string",
                        }
                    },
                    "required": ["create_if_missing", "name"],
                    'additionalProperties': False
                },
                "management_security_group": {
                    "type": "object",
                    "properties": {
                        "cidr": {
                            "type": "string",
                        },
                        "create_if_missing": {
                            "enum": [True, False],
                        },
                        "name": {
                            "type": "string",
                        }
                    },
                    "required": ["create_if_missing", "name", "cidr"],
                    'additionalProperties': False
                },
                "neutron_supported_region": {
                    "enum": [True, False],
                },
                "neutron_url": {
                    "type": "string",
                },
                "router": {
                    "type": "object",
                    "properties": {
                        "create_if_missing": {
                            "enum": [True, False],
                        },
                        "name": {
                            "type": "string",
                        }
                    },
                    "required": ["create_if_missing", "name"],
                    'additionalProperties': False
                },
                "subnet": {
                    "type": "object",
                    "properties": {
                        "cidr": {
                            "type": "string",
                        },
                        "create_if_missing": {
                            "enum": [True, False],
                        },
                        "ip_version": {
                            "enum": [4, 6],
                        },
                        "name": {
                            "type": "string",
                        },
                        "dns_nameservers": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        }
                    },
                    "required": ["create_if_missing", "name", "ip_version",
                                 "cidr", "dns_nameservers"],
                    'additionalProperties': False
                }
            },
            'additionalProperties': False,
        },
        "dev": {
            "type": "object"
        },
        'additionalProperties': False,
    }
}
