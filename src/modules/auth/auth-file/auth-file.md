AuthFile Module Documentation {#mod_auth_file_main}
==============================================================

@brief Documentation for a backend authentication module that stores its config in XML.

[TOC]

Introduction {#mod_auth_file_intro}
===================================

The module Auth-File is an **authentication backend** module.
It listens to events generated by **authentication source** module (like `Wiegand`). These events
contains credentials. This module verify the credential and either grant or deny access.
Granting or denying access means sending a message to the application. This module doesn't open a door
or perform action on its own. 


@note This module is suitable only for a low number of users / cards / groups.
The whole configuration lives in memory so this is where this limitation comes from.


Configuration Options {#mod_auth_file_user_config}
===================================================

Options    | Options     | Description                                                           | Mandatory
-----------|-------------|-----------------------------------------------------------------------|-----------
instances  |             | List of configured auth file instance                                 | YES
--->       | name        | Configure of one particular led device                                | YES
--->       | auth_source | Which device (auth source) we listen to. Can appear multiple times.   | YES
--->       | config_file | Path to the config file that holds permissions data                   | YES
--->       | target      | Name of the target (door) that we are authenticating against          | NO

Notes:
  + If the `target` is not present, the module assumes the default target, and will ignore target-specific
permissions.
  + the `config_file` path is relative to the working directory of Leosac.
  + You can enter multiple `auth_source` device. The module instance will listen to all of them.

@warning The `target` field is prefixed by the instance name and a dot when checking for permission
in the permission configuration file. This makes it easier to synchronize: you put all
configuration in the permission file and simply sync everything, the name of the door will
adapt based on the instance name. Assuming `instance_name` being `rpi-1` and `target` being
`door1` the matching name in the permission file shall be `rpi-1.door1`.


Configuration reload {#mod_auth_cfg_reload}
============================================

If you made modification to the **module's configuration file** it is possible
to request reloading of this config without having to restart Leosac.
Sending `SIGHUP` to the Leosac process will trigger an asynchronous
reload of the configuration: during the time it takes to load the new
configuration, the old configuration is still used.

Users {#mod_auth_user}
======================

Users are obviously a core component of an authentication module. The users
will map to group, credentials, etc.
Users can hold additional property, like their name, email address, or
the status of their account (`enabled`, or `disabled`).

Declaring the users {#mod_auth_user_declare}
--------------------------------------------

This section is about describing how to declare users.
This takes place in the additional config file.

Options | Options | Options        | Description                                             | Mandatory
--------|---------|----------------|---------------------------------------------------------|-----------
users   |         |                | List of users we declare                                | YES
--->    | user    |                | Declaration of one user                                 | YES
--->    | --->    | name           | Globally unique name to identify a user.                | YES
--->    | --->    | firstname      | The firstname of the user.                              | NO
--->    | --->    | lastname       | The family name of the user                             | NO
--->    | --->    | email          | An email address for the user.                          | NO
--->    | --->    | validity_start | Date when the user starts becoming valid / enabled      | NO
--->    | --->    | validity_end   | Date when the user becomes invalid / disabled           | NO
--->    | --->    | enabled        | A boolean to fully enable or disable an account         | NO (defaults to `true`)

The datetime format for `validity_{start,end}` is this: `%d/%m/%Y %H:%M` (see man (3) `strptime`).

### Example {#mod_auth_user_declare_example}

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.xml
<users>
    <user>
        <name>edgar_hoover</name>
        <firstname>Edgar</firstname>
        <lastname>Hoover</lastime>
        <email>eh@fbi.gov</email>

        <validity_start>25/10/2015 17:05</validity_start>
    </user>
</users>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Credentials Type {#mod_auth_cred}
=================================

A credentials maps to a user.

3 types of credentials are supported:
   1. WiegandCard
   2. PINCode
   3. WiegandCardPin
   
All credentials type share 4 optional properties that you can configure per credentials:
   1. `id`: The id of the credentials. Used when mapping credentials to schedules. This can be whatever you want,
       as long as it is unique.
   2. `enabled`: Is the card active? If true, the credentials can be used, otherwise it will look like it
       doesn't exist.
   3. `validity_start`: Optional date at which the credentials becomes active.
   4. `validity_end`: Optional date at which the credentials stops being active


It is possible to omit the `id` field. It is necessary only if you plan to map credentials directly to
schedules, instead of mapping user to schedules. The direct mapping of credentials to schedules can be used
to create temporary cards with more privilege than the user usually have.

WiegandCard {#mod_auth_cred_wiegandcard}
-----------------------------------------

This credentials is simply a Wiegand card number. It is qualified through a string
representing the card id, and an integer representing the number of meaningful bits in 
the card id.

Options          | Options        | Description                                                           | Mandatory
-----------------|----------------|-----------------------------------------------------------------------|------------
WiegandCard      |                | Defines a WiegandCard credential                                      | NO
--->             | card_id        | The id of the card, text string (`aa:bb:cc:dd`)                       | **YES**
--->             | bits           | Number of meaningful bits                                             | **YES**


PINCode {#mod_auth_cred_pincode}
---------------------------------

This credentials is simply a PIN code. The number of character in the code is variable.

Options          | Options        | Description                                                           | Mandatory
-----------------|----------------|-----------------------------------------------------------------------|------------
PINCode          |                | Defines a PINCode that will be a credentials                          | NO
--->             | pin            | The PIN code to be used. This is a string.                            | **YES**


WiegandCardPin {#mod_auth_cred_wiegandcard_pin}
------------------------------------------------

This is the combination of a PIN code a WiegandCard. This is currently the most complex credential type.

Options          | Options        | Description                                                           | Mandatory
-----------------|----------------|-----------------------------------------------------------------------|------------
WiegandCardPin   |                | Defines a credentials composed of a card and a PIN code               | NO
--->             | pin            | The PIN code to be used. This is a string.                            | **YES**
--->             | card_id        | The id of the card, text string (`aa:bb:cc:dd`)                       | **YES**
--->             | bits           | Number of meaningful bits                                             | **YES**


Example {#mod_auth_cred_example}
--------------------------------

Below an example for each of those credentials:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.xml
<credentials>
    <map>
        <user>llamasticot</user>
        <WiegandCard>
            <card_id>aa:bb:cc:dd</card_id>
            <bits>32</bits>
            <enabled>false</enabled>
        </WiegandCard>
    </map>
    <map>
        <user>MY_USER</user>
        <PINCode>
            <id>my_unique_id_for_this_cred</id>
            <pin>1234</pin>
        </PINCode>
    </map>
    <map>
        <user>Toto</user>
        <WiegandCardPin>
            <card>cc:dd:ee:ff</card>
            <pin>1234</pin>
        </WiegandCardPin>
    </map>
</credentials>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Groups {#mod_auth_group}
===================================

The module also supports groups. A user can be in multiple groups, and will collect
permissions from all the groups he's a member of.

There is no definition of groups, they are lazily created when mapping users to them.

Mapping user to group {#mod_auth_user_to_group}
-----------------------------------------------

A `<group_mapping>` block can be used to map user to groups.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.xml
<group_mapping>
    <map>
        <group>Admins</group>
        <user>MY_USER</user>
        <user>Toto</user>
    </map>
</group_mapping>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Note**: It is *not* possible to map credentials directly to group.  


Schedules {#mod_auth_schedule}
=============================

Schedules can be defined. They represents time-frame where access **is granted**.
Schedules are then mapped to user or to group.

They can apply to any `auth_target` (aka doors) or they can target specific doors
only. This is configured when mapping a schedule, so that the same schedule
can be better reused.

See below for an example of how to declare schedules.

Declaring schedules {#mod_auth_sched_declare}
---------------------------------------------

Options           | Options     | Options    | Options | Description                                           | Mandatory
------------------|-------------|------------|---------|-------------------------------------------------------|-----------
schedules         |             |            |         | We declare our schedules here                         | YES
--->              | schedule    |            |         | Description of on schedule entry                      | YES
--->              | --->        | name       |         | A unique name for a schedule                          | YES
--->              | --->        | "weekday"  |         | A day of the week (`monday`, `sunday`, ...)           | NO
--->              | --->        | --->       | start   | Start hour (format is `hh:mm`)                        | NO
--->              | --->        | --->       | end     | End hour (format is `hh:mm`)                          | NO


### Example {#mod_auth_sched_declare_example}

This is a simple example that declares one schedule, named `my_schedule`. It would grants access 
anytime on monday, and wednesday from 11h to 13h and from 17h to 19h.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.xml
<schedules>
    <schedule>
        <name>my_schedule</name>
         <monday>
            <start>00:00</start>
            <end>23:59</end>
        </monday>
        <wednesday>
            <start>11:00</start>
            <end>13:00</end>
        </wednesday>
        <wednesday>
            <start>17:00</start>
            <end>19:00</end>
        </wednesday>
    </schedule>
</schedules>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Schedules Mapping {#mod_auth_schedule_map}
------------------------------------------

Schedules can, or rather must, be referenced by name. They can be mapped to either
`users`, `groups`, or directly to `credentials`.

Options           | Options     | Options    | Description                                                           | Mandatory
------------------|-------------|------------|-----------------------------------------------------------------------|-----------
schedules_mapping |             |            | Defines the mapping between schedule and user/group/we                | YES
--->              | map         |            | One mapping entry                                                     | YES
--->              | --->        | schedule   | Which schedule are we mapping                                         | YES
--->              | --->        | user       | To which user are we applying the schedule(s)                         | NO
--->              | --->        | group      | To which group are we applying the schedules(s)                       | NO
--->              | --->        | credential | To which credential (identified by its `id`) do we apply the schedule | NO
--->              | --->        | door       | Name of the auth target the mapping apply to                          | NO

Note that `schedule`, `user` and `group` can be used multiple times in the same mapping entry.


### Example {#mod_auth_schedule_map_example}

There is 2 mappings entry in the following example.
   1. The first maps 2 schedules, `name_of_schedule` and `name_of_another_schedule` and applies them
      to the user `My_User`, `A_Second_User` and to anyone who is a member of the group `the_whole_group_has_the_schedule`.
   2. The seconds enable the `sysadmin_access_schedule` to the `sysadmins` group when the authentication
      attempt target the `sysadmin_room`. See the `target` field in the [module options](@ref mod_auth_file_user_config).

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.xml
<schedules_mapping>
   <map>
       <schedule>name_of_schedule</schedule>
       <schedule>name_of_another_schedule</schedule>
       <user>My_User</user>
       <user>A_Second_User</user>
       <group>the_whole_group_has_the_schedule</group>
   </map>
   <map>
       <schedule>sysadmin_access_schedule</schedule>
       <group>sysadmins</group>
       <door>sysadmin_room</door>
   </map>
</schedules_mapping>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Example {#mod_auth_file_example}
================================

This is the module configuration in the main config file.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.xml
<module>
    <name>AUTH-MANAGER-FILE</name>
    <file>libauth-file.so</file>
    <level>41</level>
    <module_config>
        <instances>
            <instance>
                <name>AUTH_CONTEXT_1</name>
                <auth_source>MY_WIEGAND_1</auth_source>
                <auth_source>MY_WIEGAND_2</auth_source>
                <config_file>file_auth.xml</config_file>
            </instance>
        </instances>
    </module_config>
</module>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


This is a possible content of the file designed by the `config_field` config entry for
the module ("file_auth.xml" based on the previous example).

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.xml
<root>
    <users>
        <user>
            <name>MY_USER</name>
        </user>
    </users>

    <!--
    Maps WiegandCard to user
    -->
    <credentials>
        <map>
            <user>MY_USER</user>
            <WiegandCard>
                <card_id>80:83:a0:40</card_id>
                <bits>32</bits>
            </WiegandCard>
        </map>
        <map>
            <user>MY_USER</user>
            <PINCode>
                <pin>1234</pin>
            </PINCode>
        </map>
    </credentials>

    <schedules>
        <schedule>
            <name>all</name>
            <!-- Has full access on monday and sunday -->
            <monday>
                <start>00:00</start>
                <end>23:59</end>
            </monday>
            <tuesday>
                <start>00:00</start>
                <end>23:59</end>
            </tuesday>
            <wednesday>
                <start>00:00</start>
                <end>23:59</end>
            </wednesday>

            <sunday>
                <start>00:00</start>
                <end>23:59</end>
            </sunday>
        </schedule>
    </schedules>

    <schedules_mapping>
        <map>
            <schedule>all</schedule>
            <user>MY_USER</user>
        </map>
    </schedules_mapping>

</root>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Notes {#mod_auth_file_notes}
============================

Check the [module object documentation](@ref Leosac::Module::Auth::AuthFileModule).