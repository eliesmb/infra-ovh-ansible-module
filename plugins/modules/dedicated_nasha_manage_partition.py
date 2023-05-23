#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = '''
---
module: dedicated_nasha_manage_partition
short_description: Create a nasha partition.
description:
    - Create a nasha partition with specified ACL and manage snapshots.
author: Digimind SRE Team
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
    nas_partition_acl:
        required: false
        type: list
        default: []
        description:
            - List of dictionaries specifying the ACLs. Each dictionary should contain the following keys
            - The IP address or CIDR range for the ACL
            - The type of ACL, either readwrite or readonly. ( Default 'readwrite')

'''

EXAMPLES = '''
- name: Create a nasha partition with specified ACL and configure snapshot
  synthesio.ovh.dedicated_nasha_manage_partition:
    nas_service_name: "{{ nas_service_name }}"
    nas_partition_name: "{{ nas_partition_name }}"
    nas_partition_size: 10
    nas_protocol: NFS
    nas_partition_acl:
      - ip: XX.XX.XX.XX/32
        type: readwrite
      - ip: XX.XX.XX.XX/32
        type: readonly
      - ip: XX.XX.XX.XX/32
'''

RETURN = '''
changed:
    description: Indicates whether the module made any changes.
    type: bool
'''

from ansible_collections.synthesio.ovh.plugins.module_utils.ovh import (
    ovh_api_connect,
    ovh_argument_spec,
)

try:
    from ovh.exceptions import APIError, ResourceNotFoundError

    HAS_OVH = True
except ImportError:
    HAS_OVH = False


def run_module():
    module_args = ovh_argument_spec()
    module_args.update(
        dict(
            nas_service_name=dict(required=True),
            nas_partition_name=dict(required=True),
            nas_partition_size=dict(required=True),
            nas_protocol=dict(required=True, choices=['NFS', 'CIFS', 'NFS_CIFS']),
            nas_partition_acl=dict(required=False, type="list", default=[]),
        )
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    client = ovh_api_connect(module)

    nas_service_name = module.params['nas_service_name']
    nas_partition_name = module.params['nas_partition_name']
    nas_partition_size = module.params['nas_partition_size']
    nas_protocol = module.params['nas_protocol']
    nas_partition_acl = module.params['nas_partition_acl']

    # Create partition
    if not module.check_mode:
        try:
            client.post(
                '/dedicated/nasha/{0}/partition'.format(nas_service_name),
                size=nas_partition_size,
                partitionName=nas_partition_name,
                protocol=nas_protocol,
            )
        except APIError as api_error:
            module.fail_json(msg="Failed to create partition: %s" % api_error)
    else:
        # Get partition
        try:
            client.get('/dedicated/nasha/{0}'.format(nas_service_name))
        except (APIError, ResourceNotFoundError) as error:
            module.fail_json(msg="Failed to get partition: %s" % error)

    # Set partition ACL
    if nas_partition_acl:
        existing_acls = []
        try:
            existing_acls = client.get(
                '/dedicated/nasha/{0}/partition/{1}/access'.format(
                    nas_service_name, nas_partition_name
                )
            )
        except (APIError, ResourceNotFoundError):
            pass

        # Check if ACLs have changed
        acl_changes = []
        for acl in nas_partition_acl:
            acl_ip = acl.get('ip')
            acl_type = acl.get('type', 'readwrite')

            # Check if ACL already exists
            acl_exists = any(
                existing_acl.get('ip') == acl_ip
                and existing_acl.get('type') == acl_type
                for existing_acl in existing_acls
            )

            # If ACL does not exist or type is different, mark it as changed
            if (
                not acl_exists
                or acl_exists
                and not any(
                    existing_acl.get('ip') == acl_ip
                    and existing_acl.get('type') != acl_type
                    for existing_acl in existing_acls
                )
            ):
                acl_changes.append(acl)

        if acl_changes:
            if not module.check_mode:
                for acl in acl_changes:
                    acl_ip = acl.get('ip')
                    acl_type = acl.get('type', 'readwrite')
                    try:
                        client.post(
                            '/dedicated/nasha/{0}/partition/{1}/access'.format(
                                nas_service_name, nas_partition_name
                            ),
                            ip=acl_ip,
                            type=acl_type,
                        )
                    except APIError as api_error:
                        module.fail_json(
                            msg="Failed to set partition ACL: %s" % api_error
                        )

                module.exit_json(
                    msg="ACLs of {} partition have been updated".format(
                        nas_partition_name
                    ),
                    changed=True,
                )
            else:
                module.exit_json(
                    msg="ACLs of {} partition would be updated".format(
                        nas_partition_name
                    ),
                    changed=True,
                )
        else:
            module.exit_json(
                msg="No changes required for ACLs of {} partition".format(
                    nas_partition_name
                ),
                changed=False,
            )
    else:
        module.exit_json(
            msg="No ACL specified. Skipping setting partition ACL.", changed=False
        )


def main():
    if not HAS_OVH:
        raise ImportError("ovh Python module is required for this script")

    run_module()


if __name__ == "__main__":
    main()
