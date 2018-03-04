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
        self._session.verify = self.boolean(self.params['validate_certs'])
        self._session.auth = (self.params['access_key'], self.params['secret_key'])

    def process(self):
        stack = None
        services = None

        try:
            self.log("Check mode: " + str(self.check_mode))
            self.init()
            environment = self.find_environment(self.params['url'], self.params['environment'])
            stack = self.find_stack(environment, self.params['stack'])

            if self.params['state'] == 'present':
                self.log("Should have a present stack")

                if stack != None and self.params['template'] == None:
                    self.log("Stack is already up, and no info to upgrade")
                    services = self.find_stack_services(stack)

                else:
                    self.log("Should create or upgrade stack")
                    stack_template = self.search_stack_template(self.params['url'], self.params['catalog'], self.params['template'], self.params['version'])

                    if stack == None:
                        self.log("Should create stack")
                        if not self.boolean(self.check_mode):
                            stack = self.create_stack(environment, self.params['stack'], stack_template, self.params['answers'])
                            if self.boolean(self.params['wait']):
                                self.wait_for_state(stack, 'active', self.params['wait_timeout'])
                            services = self.find_stack_services(stack)
                        self.changed = True

                    elif self.is_upgrade_needed(stack, stack_template, self.params['answers']):
                        self.log("Should upgrade stack")
                        if not self.boolean(self.check_mode):
                            if stack['state'] == 'upgraded':
                                self.finish_upgrade(stack)
                                stack = self.wait_for_state(stack, 'active', self.params['wait_timeout'])
                            stack = self.upgrade_stack(stack, stack_template, self.params['answers'])
                            if self.boolean(self.params['wait']):
                                self.wait_for_state(stack, 'upgraded', self.params['wait_timeout'])
                        self.changed = True
                        services = self.find_stack_services(stack)

                    else:
                        self.log("Nothing to do")

            elif self.params['state'] == 'absent':
                self.log("Should have an absent stack")
                if stack != None:
                    self.log("Should remove stack")
                    if not self.boolean(self.check_mode):
                        self.remove_stack(stack)
                        if self.boolean(self.params['wait']):
                            self.wait_for_state(stack, 'removed', self.params['wait_timeout'])
                    self.changed = True

            self.exit_json(changed=self.changed, output=self._output, stack=stack, services=services)

        except Exception as e:
            self.fail_json(msg=e.message, output=self._output, stack=stack, services=services)

    def search_stack_template(self, url, catalog, template, version):
        if catalog == None:
            raise Exception("No catalog provided")
        if template == None:
            raise Exception("No template provided")
        self.find_catalog(url, catalog)
        catalog_entry = self.find_catalog_entry(url, catalog, template)
        if version == None:
            version = catalog_entry['defaultVersion']
        return self.find_stack_template(catalog_entry, version)

    def find_environment(self, url, environment_name):
        response = self._session.get(url + RANCHER_API_PREFIX + "/projects")
        if response.status_code == 401:
            raise Exception("Invalid access/secret key")
        environments = response.json()['data']
        for environment in environments:
            if environment['name'] == environment_name:
                return environment
        raise Exception("Can't find environment " + environment_name)

    def find_stack(self, environment, stack_name):
        response = self._session.get(environment['links']['stacks'])
        stacks = response.json()['data']
        for stack in stacks:
            if stack['name'] == stack_name:
                return stack
        return None

    def find_catalog(self, url, catalog_name):
        response = self._session.get(url + CATALOG_API_PREFIX + "/catalogs")
        catalogs = response.json()['data']
        for catalog in catalogs:
            if catalog['id'] == catalog_name:
                return catalog
        raise Exception("Can't find catalog " + catalog_name)

    def find_catalog_entry(self, url, catalog_name, template_name):
        response = self._session.get(url + CATALOG_API_PREFIX + "/templates")
        catalog_entries = response.json()['data']
        for catalog_entry in catalog_entries:
            if catalog_entry['catalogId'] == catalog_name and catalog_entry['folderName'] == template_name:
                return catalog_entry
        raise Exception("Can't find catalog entry " + template_name + " in " + catalog_name)

    def find_stack_template(self, catalog_entry, template_version):
        if not template_version in catalog_entry['versionLinks']:
            raise Exception("Can't find version " + template_version + " for " + catalog_entry['folderName'])
        response = self._session.get(catalog_entry['versionLinks'][template_version])
        return response.json()

    def create_stack(self, environment, stack_name, stack_template, answers):
        body = self.create_stack_body(stack_name, stack_template, answers)
        response = self._session.post(environment['links']['stacks'], json=body)
        if response.status_code != 201:
            self.log(str(response.status_code))
            self.log(response.text)
            raise Exception("Can't start " + stack_name)
        return response.json()

    def upgrade_stack(self, stack, stack_template, answers):
        if 'upgrade' not in stack['actions']:
            raise Exception("Stack " + stack['name'] + " is currently not upgradable")
        body = self.create_stack_body(stack['name'], stack_template, answers)
        response = self._session.post(stack['actions']['upgrade'], json=body)
        if response.status_code != 202:
            self.log(str(response.status_code))
            self.log(response.text)
            raise Exception("Can't upgrade " + stack['name'])
        return response.json()

    def create_stack_body(self, stack_name, stack_template, answers):
        return {
            "name": stack_name,
            "startOnCreate": True,
            "externalId": self.create_catalog_id(stack_template),
            "dockerCompose": stack_template['files']['docker-compose.yml'],
            "rancherCompose": stack_template['files']['rancher-compose.yml'],
            "environment": answers
        }

    def is_upgrade_needed(self, stack, stack_template, answers):
        if stack['rancherCompose'] != stack_template['files']['rancher-compose.yml']:
            self.log("rancher-compose.yml are differents")
            return True
        if stack['dockerCompose'] != stack_template['files']['docker-compose.yml']:
            self.log("docker-compose.yml are differents")
            return True
        for key, value in answers.items():
            if not key in stack['environment']:
                self.log("key " + key + " is added")
                return True
            if stack['environment'][key] != str(answers[key]):
                self.log("keys " + key + " are differents")
                self.log(stack['environment'][key])
                self.log(str(answers[key]))
                return True
        # for key, value in stack['environment'].items():
        #     if not key in answers:
        #         return True
        #     if stack['environment'][key] != answers[key]:
        #         return True
        return False

    def finish_upgrade(self, stack):
        response = self._session.post(stack['actions']['finishupgrade'], json={})

    def remove_stack(self, stack):
        response = self._session.post(stack['actions']['remove'], json={})
        if response.status_code != 202:
            self.log(str(response.status_code))
            self.log(response.text)
            raise Exception("Unable to remove " + stack['name'])

    def wait_for_state(self, stack, state, wait_timeout):
        ellapsed_time = 0
        while stack['state'] != state:
            if ellapsed_time > wait_timeout:
                raise Exception("Stack " + stack['name'] + " is stuck at state " + stack['state'])
            time.sleep(1)
            response = self._session.get(stack['links']['self'])
            stack = response.json()
            ellapsed_time = ellapsed_time + 1
        return stack

    def create_catalog_id(self, stack_template):
        return "catalog://" + stack_template['id']

    def find_stack_services(self, stack):
        response = self._session.get(stack['links']['services'])
        if response.status_code != 200:
            self.log(str(response.status_code))
            self.log(response.text)
            raise Exception("Unable to retrieve services for stack " + stack['name'])
        return response.json()['data']

    def log(self, msg, *args, **kwargs):
        self._output.append(msg % kwargs)
        super(RancherStackAnsibleModule, self).log(msg, *args, **kwargs)

def main():

    module_args = dict(
        url=dict(required=True),
        access_key=dict(required=True),
        secret_key=dict(required=True),
        catalog=dict(required=False),
        environment=dict(required=True),
        stack=dict(require=True),
        template=dict(required=False),
        version=dict(required=False),
        state=dict(required=False, choices=["present", "absent"], default="present"),
        answers=dict(required=False, type='dict', default=dict()),
        validate_certs=dict(required=False, choices=BOOLEANS, default='yes'),
        wait=dict(required=False, choices=BOOLEANS, default='yes'),
        wait_timeout=dict(required=False, type='int', default=120))

    module = RancherStackAnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True)

    module.process()

if __name__ == '__main__':
    main()
