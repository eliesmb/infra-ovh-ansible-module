#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import time
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = """
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
    nas_partition_snapshot_type
        required: false
        type: list
        default: []
        description:
            - List of snapshot types
    max_retry:
        required: false
        description: Number of retry
        default: 240
    sleep:
        required: false
        description: Time to sleep between retries
        default: 10
"""

EXAMPLES = """
- name: Create a nasha partition with specified ACL and configure snapshot
  synthesio.ovh.dedicated_nasha_manage_partition:
    nas_service_name: "{{ nas_service_name }}"
    nas_partition_name: "{{ nas_partition_name }}"
    nas_partition_size: 10
    nas_protocol: NFS
    nas_partition_acl:
      - ip: XX.XX.XX.XX/32
        type: readwrite
        state: present
      - ip: XX.XX.XX.XX/32
        type: readonly
        state: present
      - ip: XX.XX.XX.XX/32
    nas_partition_snapshot_type:
      - type: hour-1
        state: absent
      - type: day-1
        state: present
    state: "{{ state }}"
    sleep: 10
    max_retry: 50
"""

RETURN = """
changed:
    description: Indicates whether the module made any changes.
    type: bool
"""

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
            nas_protocol=dict(required=True, choices=["NFS", "CIFS", "NFS_CIFS"]),
            nas_partition_acl=dict(required=False, type="list", default=[]),
            nas_partition_snapshot_type=dict(required=False, type="list", defaults=[]),
            state=dict(required=False, default="present"),
            max_retry=dict(required=False, default=50),
            sleep=dict(required=False, default=10)
        )
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    client = ovh_api_connect(module)

    nas_service_name = module.params["nas_service_name"]
    nas_partition_name = module.params["nas_partition_name"]
    nas_partition_size = module.params["nas_partition_size"]
    nas_protocol = module.params["nas_protocol"]
    nas_partition_acl = module.params["nas_partition_acl"]
    nas_partition_snapshot_type = module.params["nas_partition_snapshot_type"]
    state = module.params["state"]
    max_retry = module.params["max_retry"]
    sleep = module.params["sleep"]

    ## Message that will be sent at the end of execution
    final_message = ""




############# PARTITION MANAGEMENT #############



    ## If partition state is absent, we delete it and exit module execution
    if state == "absent":
        try:
            ## Delete the partition
            client.delete(
                "/dedicated/nasha/{0}/partition/{1}".format(
                    nas_service_name, nas_partition_name
                )
            )
        except APIError as api_error:
            module.fail_json(msg="Failed to delete partition: %s" % api_error)

        module.exit_json(
            msg="Partition {} has been deleted.".format(nas_partition_name),
            changed=True,
        )
    ## State is present
    else:
        ## Partitions of nas
        res = client.get("/dedicated/nasha/{0}/partition".format(nas_service_name))

        ## If partition does not exists, we create it
        if not nas_partition_name in res:
            if not module.check_mode:
                try:
                    ## Create partition
                    client.post(
                        "/dedicated/nasha/{0}/partition".format(nas_service_name),
                        size=nas_partition_size,
                        partitionName=nas_partition_name,
                        protocol=nas_protocol,
                    )
                except APIError as api_error:
                    module.fail_json(msg="Failed to create partition: %s" % api_error)

                final_message = "Partition {} has been created ".format(
                    nas_partition_name
                )

                # Wait for availability of new partition
                i = 0
                while not nas_partition_name in res and i < float(max_retry):
                    time.sleep(float(sleep))
                    res = client.get(
                        "/dedicated/nasha/{0}/partition".format(nas_service_name)
                    )
                    i += 1



############# SNAPSHOT MANAGEMENT #############


                ## For every snapshot type, add or remove it depending on state
                for snapshot in nas_partition_snapshot_type:
                    snapshot_state=snapshot.get("state","present")
                    if snapshot_state == "absent":
                        ##Delete snapshot
                        try:
                            client.delete(
                                "/dedicated/nasha/{0}/partition/{1}/snapshot/{2}".format(
                                    nas_service_name, nas_partition_name, snapshot.get("type")
                                )
                            )
                        except APIError as api_error:
                            module.fail_json(
                                msg="Failed to set partition snapshot: %s" % api_error
                            )
                    else:
                        ##Add snapshot
                        try:
                            client.post(
                                "/dedicated/nasha/{0}/partition/{1}/snapshot".format(
                                    nas_service_name, nas_partition_name
                                ),
                                snapshotType=snapshot.get("type")
                            )
                        except APIError as api_error:
                            module.fail_json(
                                msg="Failed to set partition snapshot: %s" % api_error
                            )

                final_message = final_message + "with snapshot type {} ".format(
                    nas_partition_snapshot_type
                )

            ## Check mode
            else:
                ## Get partition
                try:
                    client.get("/dedicated/nasha/{0}".format(nas_service_name))
                except (APIError, ResourceNotFoundError) as error:
                    module.fail_json(msg="Failed to get partition: %s" % error)




############# ACL MANAGEMENT #############


    # Set partition ACL
    if nas_partition_acl:
        existing_acls = []
        existing_acls_formated = []
        acl_exists = []
        try:
            # Get existing ACL
            existing_acls = client.get(
                "/dedicated/nasha/{0}/partition/{1}/access".format(
                    nas_service_name, nas_partition_name
                )
            )

            # Get existing ACL of each IP
            for ip in existing_acls:
                try:
                    current_acl = client.get(
                        "/dedicated/nasha/{0}/partition/{1}/access/{2}".format(
                            nas_service_name, nas_partition_name, ip
                        )
                    )
                    existing_acls_formated.append(current_acl)

                except (APIError, ResourceNotFoundError):
                    pass

        except (APIError, ResourceNotFoundError):
            pass


        # Check if ACLs have changed
        acl_changes = []
        for acl in nas_partition_acl:
            acl_ip = acl.get("ip")
            acl_type = acl.get("type", "readwrite")
            acl_state = acl.get("state","present")

            # Check if ACL already exists
            acl_exists = any(
                existing_acl.get("ip") == acl_ip
                and existing_acl.get("type") == acl_type
                for existing_acl in existing_acls_formated
            )

            # If ACL does not exist or type is different, we append acl to acl_changes
            if (
                not acl_exists
                or acl_exists
                and not any(
                    existing_acl.get("ip") == acl_ip
                    and existing_acl.get("type") != acl_type
                    for existing_acl in existing_acls_formated
                )
            ):
                acl_changes.append(acl)

        ## Add ACLs if acl_changes is not empty
        if acl_changes:
            if not module.check_mode:
                for acl in acl_changes:
                    # If acl state is absent, we delete it
                    if acl_state == "absent":
                        # DELETE ACL
                        try:
                            client.delete(
                                "/dedicated/nasha/{0}/partition/{1}/access/{2}".format(
                                    nas_service_name, nas_partition_name, acl_ip.split("/")[0]
                                )
                            )

                        except APIError as api_error:
                            module.fail_json(
                                msg="Failed to set partition ACL: %s" % api_error
                            )
                    # ACL state is present so we add it to partition's ACLs
                    else:
                        acl_ip = acl.get("ip")
                        acl_type = acl.get("type", "readwrite")
                        try:
                            client.post(
                                "/dedicated/nasha/{0}/partition/{1}/access".format(
                                    nas_service_name, nas_partition_name
                                ),
                                ip=acl_ip,
                                type=acl_type,
                            )

                        except APIError as api_error:
                            module.fail_json(
                                msg="Failed to set partition ACL: %s" % api_error
                            )

                final_message = final_message + " And Acls for {}".format(
                    nas_partition_acl
                )

                module.exit_json(msg=final_message, changed=True)
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
