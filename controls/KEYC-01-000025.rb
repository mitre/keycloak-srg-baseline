# -*- encoding : utf-8 -*-
control "KEYC-01-000025" do
  title "Keycloak must be configured to uniquely identify and authenticate organizational users."
  desc  "
    To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 
    
    Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following.
    
    (i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and 
    (ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.
  "
  desc  "rationale", ""
  desc  "check", "
    Verify Keycloak are configured to uniquely identify and authenticate organizational users. For STIGs produced from this requirement, when Keycloak are used to authenticate processes acting on behalf of organizational users, they also must be uniquely identified and authenticated.
    
    If Keycloak are not configured to uniquely identify and authenticate organizational users, this is a finding.
    
    To confirm this setting is configured using the Keycloak admin CLI, after logging in with a privileged account, which can be done by running:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    then run the following command:
    
    kcadm.sh get-roles -r [YOUR REALM] 
    kcadm.sh get-roles -r [YOUR REALM] --effective --uusername [ORGANIZATION USER NAME] 
    
    If the command returns with any empty string or null, this is a finding.
    If the organization user does not have the appropriate roles(i.e. appropriate privileges), this is a finding. 
  "
  desc  "fix", "
    Configure Keycloak to uniquely identify and authenticate organizational users.
    
    To configure this settings using the Keycloak admin CLI, do the following from a privileged account:
    First, find the current setting for organization users: 
    
    kcadm.sh get-roles -r [YOUR REALM] 
    kcadm.sh get-roles -r [YOUR REALM] --effective --uusername [USER NAME] 
    
    Next, to uniquely identify organizational users, create roles specific to organization users with the following commands: 
    
    kcadm.sh create roles -r [YOUR REALM] -s name=[ROLE POLICY NAME] -s 'description=[ROLE POLICY DESCRIPTION LIMITING USER PERMISSIONS]'
    kcadm.sh add-roles --uusername [USER NAME] --rolename [ROLE POLICY NAME] -r [YOUR REALM]
  "
  impact 0.7
  tag severity: "high"
  tag gtitle: "SRG-APP-000148-AAA-000390"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000025"
  tag cci: ["CCI-000764"]
  tag nist: ["IA-2"]
end