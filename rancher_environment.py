#!/usr/bin/python

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: rancher_stack

short_description: A module to launch Rancher stacks

version_added: "2.4"

description:
    - "This is my longer description explaining my sample module"

options:
    name:
        description:
            - This is the message to send to the sample module
        required: true
    new:
        description:
            - Control to demo if the result of this module is changed or not
        required: false

author:
    - Maxime Wojtczak (@maxwo)
'''

EXAMPLES = '''
# Pass in a message
- name: Ensure Janitor is launched
  rancher_stack:
    rancher_url: "https://myrancher.com/"
    access_key: "XXXXX"
    secret_key: "YYYYYYYYYY"
    environment_name: "Default"
    catalog_name: "community"
    stack_name: "Janitor"
    template_name: "janitor"
    template_version: "v1.7.1"
    answers:
      FREQUENCY: 10000

- name: Ensure Janitor is removed
  rancher_stack:
    rancher_url: "https://myrancher.com/"
    access_key: "XXXXX"
    secret_key: "YYYYYYYYYY"
    environment_name: "Default"
    stack_name: "Janitor"
    state: "absent"
'''

RETURN = '''
original_message:
    description: The original name param that was passed in
    type: str
message:
    description: The output message that the sample module generates
'''

from ansible.module_utils.basic import *
import requests
import logging
import time

RANCHER_API_PREFIX = 'v2-beta'
CATALOG_API_PREFIX = 'v1-catalog'

class RancherStackAnsibleModule(AnsibleModule):
    def __init__(self, *args, **kwargs):
        self._output = []
        super(RancherStackAnsibleModule, self).__init__(*args, **kwargs)

    def init(self):
        self.changed = False
        if self.boolean(self.params['validate_certs']) == False:
            logging.captureWarnings(True)
        self._session = requests.session()
        self._session.verify = self.params['validate_certs']
        self._session.auth = (self.params['access_key'], self.params['secret_key'])

    def process(self):
        stacks = None
        hosts = None
        token = None

        try:
            self.log("Check mode: " + str(self.check_mode))
            self.init()
            environment = self.find_environment(self.params['url'], self.params['environment'])

            if self.params['state'] == 'present':
                self.log("Should have a present environment")
                template = self.find_template(self.params['url'], self.params['template'])
                if environment == None:
                    self.log("Should create an environment")
                    if not self.boolean(self.check_mode):
                        environment = self.create_environment(self.params['url'], self.params['environment'], template, self.params['description'])
                        self.wait_for_state(environment, 'active')
                    self.changed = True

                if environment != None:
                    stacks = self.find_stacks(environment)
                    hosts = self.find_hosts(environment)
                    token = self.find_token(environment)

            elif self.params['state'] == 'absent':
                self.log("Should have an absent environment")
                if environment != None:
                    self.log("Should remove environment")
                    if not self.boolean(self.check_mode):
                        self.remove_environment(environment)
                    self.changed = True

            self.exit_json(changed=self.changed, output=self._output, stacks=stacks, hosts=hosts, token=token)

        except Exception as e:
            self.fail_json(msg=e.message, output=self._output, stacks=stacks, hosts=hosts, token=token)

    def find_environment(self, url, environment_name):
        response = self._session.get(url + RANCHER_API_PREFIX + "/projects")
        if response.status_code == 401:
            raise Exception("Invalid access/secret key")
        environments = response.json()['data']
        for environment in environments:
            if environment['name'] == environment_name:
                return environment
        return None

    def find_template(self, url, name):
        response = self._session.get(url + RANCHER_API_PREFIX + "/projecttemplates")
        templates = response.json()['data']
        for template in templates:
            if template['name'] == name:
                return template
        raise Exception("Can't find template "+ template_name)

    def create_environment(self, url, name, template, description):
        body = self.create_environment_body(name, template, description)
        response = self._session.post(url + RANCHER_API_PREFIX + "/projects", json=body)
        if response.status_code != 201:
            self.log(str(response.status_code))
            self.log(response.text)
            raise Exception("Can't create environment " + name)
        return response.json()

    def create_environment_body(self, name, template, description):
        return {
            "description": description,
            "name": name,
            "projectTemplateId": template['id'],
            "allowSystemRole": True,
            "members": [ ],
            "virtualMachine": False,
            "servicesPortRange": None,
            "projectLinks": [ ]
        }

    def remove_environment(self, environment):
        if 'deactivate' in environment['actions']:
            response = self._session.post(environment['actions']['deactivate'], json={})
            environment = self.wait_for_state(environment, 'inactive')
            if response.status_code != 200:
                self.log(str(response.status_code))
                self.log(response.text)
                raise Exception("Unable to deactivate " + environment['name'])

        if 'remove' in environment['actions']:
            response = self._session.post(environment['actions']['remove'], json={})
            environment = self.wait_for_state(environment, 'removed')
            if response.status_code != 202:
                self.log(str(response.status_code))
                self.log(response.text)
                raise Exception("Unable to remove " + environment['name'])

        if 'purge' in environment['actions']:
            response = self._session.post(environment['actions']['purge'], json={})
            environment = self.wait_for_state(environment, 'removed')
            if response.status_code != 202:
                self.log(str(response.status_code))
                self.log(response.text)
                raise Exception("Unable to purge " + environment['name'])

    def find_stacks(self, environment):
        response = self._session.get(environment['links']['stacks'])
        json = response.json()
        if 'data' in json:
            return json['data']
        else:
            return []

    def find_hosts(self, environment):
        response = self._session.get(environment['links']['hosts'])
        json = response.json()
        if 'data' in json:
            return json['data']
        else:
            return []

    def find_token(self, environment):
        response = self._session.get(environment['links']['registrationTokens'])
        self.log("token: " + str(response.status_code))
        tokens = response.json()['data']
        if len(tokens) > 0:
            return tokens[0]
        else:
            return self._session.post(environment['links']['registrationTokens'], json={"type":"registrationToken"}).json()

    def wait_for_state(self, environment, state):
        ellapsed_time = 0
        while environment['state'] != state:
            time.sleep(1)
            response = self._session.get(environment['links']['self'])
            environment = response.json()
        return environment

    def log(self, msg, *args, **kwargs):
        self._output.append(msg % kwargs)
        super(RancherStackAnsibleModule, self).log(msg, *args, **kwargs)

def main():

    module_args = dict(
        url=dict(required=True),
        access_key=dict(required=True),
        secret_key=dict(required=True),
        environment=dict(required=True),
        description=dict(required=False, default=""),
        template=dict(required=False, default="Cattle"),
        state=dict(required=False, choices=["present", "absent"], default="present"),
        validate_certs=dict(required=False, choices=BOOLEANS, default='yes'))

    module = RancherStackAnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True)

    module.process()

if __name__ == '__main__':
    main()
