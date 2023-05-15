#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = '''
---
module: dedicated_nasha_manage_partition
short_description: Create a nasha partition.
description:
    - Create a nasha partition with specified ACL.
author: Synthesio SRE Team
requirements:
    - ovh >= 0.5.0
options:
    nas_service_name:
        required: true
        description:
        - The name of the NAS
    nas_partition_name:
        required: true
        description:
        - The name of the partition you want to create
    nas_partition_size:
        required: true
        description:
        - The size of the partition you want to create. Must be >= 10 Gb
    nas_protocol:
        required: true
        choices: ['NFS', 'CIFS', 'NFS_CIFS']
        description:
        - The protocol of the partition
    nas_partition_acl_type:
        required: false
        choices: ['readonly', 'readwrite']
        description:
        - The type of the ACL you want to create
    nas_partition_acl:
        required: true
        description:
        - IP or list of IPs you want to create access for
'''

EXAMPLES = '''
- name: Create a nasha partition with specified ACL
  synthesio.ovh.dedicated_nasha_manage_partition:
    nas_service_name: "{{ nas_service_name }}"
    nas_partition_name: "{{ nas_partition_name }}"
    nas_partition_size: 10
    nas_protocol: NFS
    nas_partition_acl_type: readwrite
    nas_partition_acl:
      - XX.XX.XX.XX/32
      - XX.XX.XX.XX/32
'''

RETURN = '''
changed:
    description: Indicates whether the module made any changes.
    type: bool
'''

from ansible_collections.synthesio.ovh.plugins.module_utils.ovh import (
    ovh_api_connect, ovh_argument_spec
)

try:
    from ovh.exceptions import APIError, ResourceNotFoundError
    HAS_OVH = True
except ImportError:
    HAS_OVH = False


def run_module():
    module_args = ovh_argument_spec()
    module_args.update(dict(
        nas_service_name=dict(required=True),
        nas_partition_name=dict(required=True),
        nas_partition_size=dict(required=True),
        nas_protocol=dict(required=True),
        nas_partition_acl_type=dict(required=False),
        nas_partition_acl=dict(required=True, type="list")
    ))

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    client = ovh_api_connect(module)

    nas_service_name = module.params['nas_service_name']
    nas_partition_name = module.params['nas_partition_name']
    nas_partition_size = module.params['nas_partition_size']
    nas_partition_acl = module.params['nas_partition_acl']
    nas_partition_acl_type = module.params['nas_partition_acl_type']
    nas_protocol = module.params['nas_protocol']

    # Create partition
    if not module.check_mode:
        try:
            client.post(
                '/dedicated/nasha/{0}/partition'.format(nas_service_name),
                size=nas_partition_size,
                partitionName=nas_partition_name,
                protocol=nas_protocol
            )
        except APIError as api_error:
            module.fail_json(msg="Failed to create partition: %s" % api_error)
    else:
        try:
            client.get('/dedicated/nasha/{0}'.format(nas_service_name))

        except APIError as api_error:
            module.fail_json(msg="Failed to get partition: %s" % api_error)

    # Set partition ACL
    if not module.check_mode:
        for ip_acl in nas_partition_acl:
            try:
                client.post(
                    '/dedicated/nasha/{0}/partition/{1}/access'.format(
                        nas_service_name, nas_partition_name
                    ),
                    ip=ip_acl,
                    type=nas_partition_acl_type
                )
                module.exit_json(
                    msg="IP {} has been added to ACL of {} partition".format(
                        ip_acl, nas_partition_name
                    ),
                    changed=True
                )
            except APIError as api_error:
                module.fail_json(msg="Failed to set partition ACL: %s" % api_error)


def main():
    run_module()

if __name__ == '__main__':
    main()
