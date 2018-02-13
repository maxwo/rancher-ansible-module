# Rancher Ansible modules

Ansible modules to provision Rancher.

Supports check to make it more reliable to provision.

## Environment provisioning

To create a Catte "TEST" environment, use the rancher_environment task:

    - name: Ensure environment TEST is created
      rancher_environment:
        url: "{{ rancher_url }}"
        access_key: "{{ access_key }}"
        secret_key: "{{ secret_key }}"
        environment: TEST
        template: Cattle
        description: This is my test environment

And then:

    admin          ALL = (ALL) NOPASSWD: ALL
