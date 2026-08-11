..
      Copyright 2015 Mirantis Inc. All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

.. _tutorial_step_3_benchmarking_with_existing_users:

Step 3. Running Task against OpenStack with read only users
===========================================================

.. contents::
   :local:

Motivation
----------

There are two very important reasons from the production world of why it is
preferable to use some already existing users to test your OpenStack cloud:

1. *Read-only Keystone Backends:* creating temporary users for running
scenarios in Rally is just impossible in case of r/o Keystone backends like
*LDAP* and *AD*.

2. *Safety:* Rally can be run from an isolated group of users, and if something
goes wrong, this won't affect the rest of the cloud users.


Registering an environment with existing users in Rally
-------------------------------------------------------

The information about existing users in your OpenStack cloud should be passed
to Rally at the
:ref:`environment initialization step <tutorial_step_1_setting_up_env_and_running_benchmark_from_samples>`.
The difference from the environment spec we've seen previously is that you
should set up the *"users"* section with the credentials of already existing
users. Let's call this spec file *existing_users.json*:

.. code-block:: json

    {
        "existing@openstack": {
            "auth_url": "http://example.net:5000/v3/",
            "region_name": "RegionOne",
            "endpoint_type": "public",
            "admin": {
                "username": "admin",
                "password": "pa55word",
                "user_domain_name": "Default",
                "project_name": "demo",
                "project_domain_name": "Default"
            },
            "users": [
                {
                    "username": "b1",
                    "password": "1234",
                    "user_domain_name": "Default",
                    "project_name": "testing",
                    "project_domain_name": "Default"
                },
                {
                    "username": "b2",
                    "password": "1234",
                    "user_domain_name": "Default",
                    "project_name": "testing",
                    "project_domain_name": "Default"
                }
            ]
        }
    }

This spec requires some basic information about the OpenStack cloud like the
region name, auth url, admin user credentials, and any amount of users already
existing in the system. Rally will use their credentials to generate load
against this cloud as soon as we register it as usual:

.. code-block:: console

    $ rally env create --name our_cloud --spec existing_users.json
    Using environment: 1849a9bf-4b18-4fd5-89f0-ddcc56eae4c9
    +---------------------+--------------------------------------------------+
    | uuid                | 1849a9bf-4b18-4fd5-89f0-ddcc56eae4c9             |
    | name                | our_cloud                                        |
    | status              | READY                                            |
    | created_at          | 2025-03-28T02:43:27.759702                       |
    | updated_at          | 2025-03-28T02:43:27.771702                       |
    | description         |                                                  |
    | extras              | {}                                               |
    | platform: openstack | {                                                |
    |                     |   "admin": {                                     |
    |                     |     "username": "admin",                         |
    |                     |     "password": "pa55word",                      |
    |                     |     "user_domain_name": "Default",               |
    |                     |     "project_domain_name": "Default",            |
    |                     |     "tenant_name": "demo",                       |
    |                     |     "auth_url": "http://example.net:5000/v3/",   |
    |                     |     "region_name": "RegionOne",                  |
    |                     |     "endpoint_type": "public",                   |
    |                     |     "domain_name": null,                         |
    |                     |     "https_insecure": false,                     |
    |                     |     "https_cacert": null                         |
    |                     |   },                                             |
    |                     |   "users": [                                     |
    |                     |     {                                            |
    |                     |       "username": "b1",                          |
    |                     |       "password": "1234",                        |
    |                     |       "user_domain_name": "Default",             |
    |                     |       "project_domain_name": "Default",          |
    |                     |       "tenant_name": "testing",                  |
    |                     |       "auth_url": "http://example.net:5000/v3/", |
    |                     |       "region_name": "RegionOne",                |
    |                     |       "endpoint_type": "public",                 |
    |                     |       "domain_name": null,                       |
    |                     |       "https_insecure": false,                   |
    |                     |       "https_cacert": null                       |
    |                     |     },                                           |
    |                     |     {                                            |
    |                     |       "username": "b2",                          |
    |                     |       "password": "1234",                        |
    |                     |       "user_domain_name": "Default",             |
    |                     |       "project_domain_name": "Default",          |
    |                     |       "tenant_name": "testing",                  |
    |                     |       "auth_url": "http://example.net:5000/v3/", |
    |                     |       "region_name": "RegionOne",                |
    |                     |       "endpoint_type": "public",                 |
    |                     |       "domain_name": null,                       |
    |                     |       "https_insecure": false,                   |
    |                     |       "https_cacert": null                       |
    |                     |     }                                            |
    |                     |   ]                                              |
    |                     | }                                                |
    +---------------------+--------------------------------------------------+

With this new environment being the default one, Rally will use the already
existing users instead of creating the temporary ones when launching task that
do not specify the *"users"* context.


Running tasks that uses existing users
--------------------------------------

After you have registered an environment with existing users, don't forget to
remove the *"users"* context from your task input file if you want
to use existing users, like in the following configuration file
(*boot-and-delete.json*):


.. code-block:: json

    {
        "version": 2,
        "title": "Boot and delete servers using existing users",
        "subtasks": [
            {
                "title": "Boot and delete a single server",
                "scenario": {
                    "NovaServers.boot_and_delete_server": {
                        "flavor": {
                            "name": "m1.tiny"
                        },
                        "image": {
                            "name": "^cirros.*-disk$"
                        },
                        "force_delete": false
                    }
                },
                "runner": {
                    "constant": {
                        "times": 10,
                        "concurrency": 2
                    }
                },
                "contexts": {}
            }
        ]
    }

When you start this task, it is going to use *"b1"* and *"b2"* for running
subtask instead of creating the temporary users:

.. code-block:: bash

    rally task start samples/tasks/scenarios/nova/boot-and-delete.json

It goes without saying that support of running with predefined users
simplifies the usage of Rally for generating loads against production clouds.

(based on: http://boris-42.me/rally-can-generate-load-with-passed-users-now/)
