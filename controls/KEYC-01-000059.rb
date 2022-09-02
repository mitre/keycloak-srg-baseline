# -*- encoding : utf-8 -*-
control "KEYC-01-000059" do
  title "Keycloak must be configured to allow the use of a temporary password at initial logon with an immediate change to a permanent password."
  desc  "
    Without providing this capability, an account may be created without a password. Non-repudiation cannot be guaranteed once an account is created if a user is not forced to change the temporary password upon initial logon. 
    
    Temporary passwords are typically used to allow access to applications when new accounts are created or passwords are changed. It is common practice for administrators to create temporary passwords for user accounts that allow the users to log on, yet force them to change the password once they have successfully authenticated.
  "
  desc  "rationale", ""
  desc  "check", "
    If Keycloak rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. This requirement is not applicable to service account passwords (e.g. shared secrets, pre-shared keys) or the account of last resort.
    
    Where passwords are used, such as temporary or emergency accounts, verify Keycloak are configured to allow the use of a temporary password at initial logon with an immediate change to a permanent password. This requirement may be verified by demonstration or configuration review. 
    
    If Keycloak are not configured to allow the use of a temporary password at initial logon with an immediate change to a permanent password, this is a finding.
    
    To confirm this setting is configured using the Keycloak admin CLI, after logging in with a privileged account, which can be done by running:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    then run the following command:
    
    kcadm.sh get authentication/required-actions/UPDATE_PASSWORD -r [YOUR REALM] | grep \"defaultAction\" 
    
    If configured correctly, this command should return with defaultAction set to true.
    If the command returns with any empty string or null, or if defaultAction is not set to true, this is a finding.
  "
  desc  "fix", "
    Configure Keycloak to allow the use of a temporary password at initial logon with an immediate change to a permanent password. This requirement is not applicable to service account passwords (e.g. shared secrets, pre-shared keys) or the account of last resort.
    
    To configure this settings using the Keycloak admin CLI, do the following from a privileged account:
    First, find the current setting: 
    
    kcadm.sh get authentication/required-actions/UPDATE_PASSWORD -r [YOUR REALM] 
    
    Next, configure the settings 'enabled' and 'defaultAction' or update the setting if it is already set. You can set it for the first time using the same process.
    
    kcadm.sh update authentication/required-actions/UPDATE_PASSWORD -r [YOUR REALM] -b '{\"alias\":\"UPDATE_PASSWORD\", \"name\":\"Update Profile\", \"providerId\":\"UPDATE_PASSWORD\", \"priority\":30, \"config\":{}, \"enabled\":true, \"defaultAction\":true}'
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000397-AAA-000560"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000059"
  tag cci: ["CCI-002041"]
  tag nist: ["IA-5 (1) (f)"]
end