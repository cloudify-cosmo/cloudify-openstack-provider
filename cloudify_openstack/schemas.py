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

OPENSTACK_SCHEMA = {
    "type":"object",
    "required":[
        'keystone',
        'networking',
        'compute',
        'cloudify'
    ],
    "properties":{
        "cloudify": {
            "type":"object",        
            "required":[
                'cloudify_components_package_url',
                'cloudify_package_url',
            ],
            "properties":{
                "cloudify_branch": {
                    "type":"string",                
                },
                "cloudify_components_package_path": {
                    "type":"string",                
                },
                "cloudify_components_package_url": {
                    "type":"string",                
                },
                "cloudify_package_path": {
                    "type":"string",                
                },
                "cloudify_package_url": {
                    "type":"string",                
                },
                "cloudify_packages_path": {
                    "type":"string",                
                }
            }
        },
        "compute": {
            "type":"object",        
            "required":[
                'management_server',
                'agent_servers',
                'region'
            ],
            "properties":{
                "agent_servers": {
                    "type":"object",                                    
                    "properties":{
                        "agents_keypair": {
                            "type":"object",                                                    
                            "properties":{
                                "auto_generated": {
                                    "type":"object",                                                                    
                                    "properties":{
                                        "private_key_target_path": {
                                            "type":"string",                                                                                    
                                        }
                                    }
                                },
                                "externally_provisioned": {
                                    "enum": [ True, False ],
                                },
                                "name": {
                                    "type":"string",                                                                    
                                }
                            }
                        }
                    }
                },
                "management_server": {
                    "type":"object",                                    
                    "properties":{
                        "instance": {
                            "type":"object",                                                    
                            "properties":{
                                "externally_provisioned": {
                                    "enum": [ True, False ],
                                },
                                "flavor": {
                                    "type":"number",
                                },
                                "image": {
                                    "type": ["number", "string"],
                                },
                                "name": {
                                    "type":"string",                                                                    
                                }
                            }
                        },
                        "management_keypair": {
                            "type":"object",                                                    
                            "properties":{
                                "auto_generated": {
                                    "type":"object",                                                                    
                                    "properties":{
                                        "private_key_target_path": {
                                            "type":"string",                                                                                    
                                        }
                                    }
                                },
                                "externally_provisioned": {
                                    "enum": [ True, False ],
                                },
                                "name": {
                                    "type":"string",                                                                    
                                }
                            }
                        },
                        "user_on_management": {
                            "type":"string",                                                    
                        },
                        "userhome_on_management": {
                            "type":"string",                                                    
                        }
                    }
                },
                "region": {
                    "type":"string",                                    
                }
            }
        },
        "keystone": {
            "type":"object",                    
            "properties":{
                "auth_url": {
                    "type":"string",                                    
                },
                "password": {
                    "type":"string",                                    
                },
                "tenant_name": {
                    "type":"string",                                    
                },
                "username": {
                    "type":"string",                                    
                }
            }
        },
        "networking": {
            "type":"object",                    
            "properties":{
                "agents_security_group": {
                    "type":"object",                                    
                    "properties":{
                        "externally_provisioned": {
                            "enum": [ True, False ],
                        },
                        "name": {
                            "type":"string",                                                    
                        }
                    }
                },
                "ext_network": {
                    "type":"object",                                    
                    "properties":{
                        "externally_provisioned": {
                            "enum": [ True, False ],
                        },
                        "name": {
                            "type":"string",                                                    
                        }
                    }
                },
                "int_network": {
                    "type":"object",                                    
                    "properties":{
                        "externally_provisioned": {
                            "enum": [ True, False ],
                        },
                        "name": {
                            "type":"string",                                                    
                        }
                    }
                },
                "management_security_group": {
                    "type":"object",                                    
                    "properties":{
                        "cidr": {
                            "type":"string",
                        },
                        "externally_provisioned": {
                            "enum": [ True, False ],
                        },
                        "name": {
                            "type":"string",                                                    
                        }
                    }
                },
                "neutron_supported_region": {
                    "enum": [ True, False ],
                },
                "neutron_url": {
                    "type":"string",                                    
                },
                "router": {
                    "type":"object",                                    
                    "properties":{
                        "externally_provisioned": {
                            "enum": [ True, False ],
                        },
                        "name": {
                            "type":"string",                                                    
                        }
                    }
                },
                "subnet": {
                    "type":"object",                                    
                    "properties":{
                        "cidr": {
                            "type":"string",
                        },
                        "externally_provisioned": {
                            "enum": [ True, False ],
                        },
                        "ip_version": {
                            "enum": [ 4, 6 ],
                        },
                        "name": {
                            "type":"string",                                                    
                        },
                        "dns_nameservers": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        }
    }
}