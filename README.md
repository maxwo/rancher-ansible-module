# Rancher Ansible modules

Ansible modules to provision Rancher.

Supports check to make it more reliable to provision.

## Environment provisioning

To create an environment, use the rancher_environment task:

    - name: Ensure environment TEST is created
      rancher_environment:
        state: present
        url: "{{ rancher_url }}"
        access_key: "{{ access_key }}"
        secret_key: "{{ secret_key }}"
        environment: TEST
        template: Cattle
        description: This is my test environment

## Stack provisioning

To launch a stack with tuned answer, use the rancher_stack task:

    - name: Ensure Janitor is launched
      rancher_stack:
        state: present
        url: "{{ rancher_url }}"
        access_key: "{{ access_key }}"
        secret_key: "{{ secret_key }}"
        environment: "Default"
        catalog: "community"
        stack: "Janitor"
        template: "janitor"
        version: "v1.7.1"
        answers:
          FREQUENCY: 18000
