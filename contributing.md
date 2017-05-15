# Contributing Details

## Notes
Each module currently has the base `Netscaler` class and any additional sub-classes that are needed for the module execution. The goal is to have all of the classes function as a module_utils file, but are currently appended to each module for ease of consumption. This also means that each base documentation option must be included in each module instead of using `extends_documentation_fragment`.

Enhancements and bug fixes are welcome, just submit a pull request and provide some information on why it is needed and what it is aimed to enhance or fix.

## Classes Vs. Methods
The design method for creating a new class versus creating methods inside of an existing class are:

1. Creating, Updating, and Deleting objects get their own class.
2. Binding objects together should be done with methods inside the class that corresponds to first class listed in the API Endpoint.

##### EXAMPLE:
Creating, updating, and deleting lbvserver objects would be its own defined class, LBVServer.

Binding an lbvserver object to a servicegroup object would be a set of methods in the LBVServer class since the goal is to bind obects together and the API endpoint is "**lbvserver**_servicegroup_binding"

## Class Methodology
Each new class should inherit the base `Netscaler` class, which is where all common methods are defined. The new sub-class should define the `api_endpoint` for the object when defining `__init__`. Sub-classes should only have methods defined when:

1. There is a need to override the base class' implementation.
  * Example would be methods that define a `name` key, but the particular API endpoint does not follow the "standard" Nitro naming convention (ServiceGroup is an example).
2. The class needs a method that is unique to it.
  * Example would be a binding method.

## Method Methodology
Most methods defined are used to either make an API request to the Netscaler, or to modify the data returned from an API request. There are a few Ansible specific methods that are used to handle the logic of the corresponding Ansible Module (thus making the creation of new modules easier and consistent with existing modules):

1. `config_new` is used to handle the logic of configuring a new object on the Netscaler. This supports checkmode, fails the module if an API request fails, and returns the config key that is returned by the Ansible Module.

2. `config_update` is used to handle the logic of updating and existing object's configuration on the Netscaler. This supports checkmode, fails the module if an API request fails, and returns the config key that is returned by the Ansible Module.

3. `config_delete` is used to handle the logic of deleting an existing object on the Netscaler. This supports checkmode, fails the module if an API request fails, and returns the config key that is returned by the Ansible Module.

Since these are the only 3 modules that are Ansible specefic, and these modules use methods in the class to perform API requests, it is easy to use and debug in a Python shell.

Methods used to handle logic should not make API requests, but should call a method whose sole purpose is to return either the response or response content from an API request.

Methods that make API requests should not be handling logic required to obtain some other goal.

## Module Methodology
The base `Argument Specs` that should be supported are:
```
host=dict(required=True, type="str"),
port=dict(required=False, type="int"),
username=dict(fallback=(env_fallback, ["ANSIBLE_NET_USERNAME"])),
password=dict(fallback=(env_fallback, ["ANSIBLE_NET_PASSWORD"]), o_log=True),
use_ssl=dict(default=True, type="bool"),
validate_certs=dict(default=False, type="bool"),
provider=dict(required=False, type="dict"),
state=dict(choices=["absent", "present"], default="present", type="str"),
partition=dict(required=False, type="str")
```
>Provider should not log password values, and should be overridden by duplicate values specified as a local param.

The module specific args are put into a dictionary, with the unused (null value) arguments being omitted. This method is done to prevent existing objects from being accidently changed to Netscaler's default value.

After login, the very next step should be to switch to the partition if defined in the module args. This is important since the Netscaler does not support passing a "partition" argument with an API request. The `Netscaler`'s `login` and `switch_partition` methods handle this for you.

The next step is to retrieve the object or binding configuration from the Netscaler (this should be based on the object's name).

The next step is to determine if the `state` is set to "present" or "absent" and pass the necessary args to either a `change_config` or `delete_config` function. These functions should handle the rest of the necessary Ansible logic and return back the results dictionary that the Ansible Module will return back to the terminal.

The `change_config` function will need to determine if the configuration needs to create a new object or binding, or update the existing configuration. The `get_diff` method returns a tuble of two values:

1. config_method can be either:
  * "new" - meaning the object or binding currently does not exist.
  * "update" - meaning the object or binding does exist, but there are differences between what was submitted in the task and the current configuration.
  * "none" - meaning the proposed and existing configuration are identical.
2. config_diff can be either:
  * The configuration difference between proposed and existing configuration (only values that are different than existing are  in the dict).
  * An empty dict if proposed and existing are identical.

Once you have the config_method and config_diff, you can perfrom any desired tests and use the config_new or config_update methods to make the necessary changes.

The `delete_config` function should check that the object or binding exists on the Netscaler, and then call the `config_delete` method if there is configuration to be removed.

