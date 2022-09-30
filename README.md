# Work in Progress

# keycloak-srg-baseline


## Getting Started


# Running This Baseline Directly from Github

```
# How to run
```

### Different Run Options



## Running This Baseline from a local Archive copy

Obtain docker Keycloak image and set ADMIN username/password
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

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results.

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Testing with Kitchen


### Setup Environment


### Execute Tests


## Authors


## Special Thanks


## Contributing and Getting Help


### NOTICE



### NOTICE



### NOTICE



### NOTICE

