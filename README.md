# keycloak-srg-baseline (Work In Progress)

This Ansible role hardens RedHat's [Keycloak](https://www.keycloak.org/) SSO application in line with DISA's Authentication, Authorization and Accounting Server Security Requirements Guide (AAA SRG).

This role is intended to work on Keycloak versions based off of Quarkus (tested with version 19), both the container and bare-metal installation versions.

## Requirements

- Ansible v2.11+
- Python v3.X

## Getting Started

Copy this repository locally.

``` bash
git clone https://github.com/mitre/keycloak-srg-baseline.git
cd keycloak-srg-baseline/spec/ansible
```

Edit the `vars/main.yml` file with values specific to the Keycloak deployment under test.

Execute the playbook.

``` bash
ansible-playbook playbook.yml --extra-vars keycloak_admin_password=<your admin password>
```

## Launching and working with the Keycloak image

Obtain the official Keycloak container image and set the admin username/password:
```
docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:18.0.2 start-dev
```
(Optional) To access Keycloak CLI:
```
docker exec -it <DockerID> bash
```
(Optional) Keycloak's primary executable for shell commands is kcadm.sh. To add kcadm.sh to Keycloak's CLI PATH:
```
export KEYCLOAK_HOME=/opt/keycloak/
export PATH=$PATH:$KEYCLOAK_HOME/bin
```
(Optional) To access Keycloak's GUI:
```
kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password admin
```
Then navigate to [localhost:8080/](localhost:8080/) in your browser.  
To run the Ansible playbook against Keycloak:
```
cd spec/ansible
ansible-playbook playbook.yml
```

## Testing with Kitchen

TODO: describe pipeline

## Authors
- [Brett Warren](https://github.com/brett-w)
- [Henry Xiao](https://github.com/HenryXiaoHX)
- [Will Dower](https://github.com/wdower)