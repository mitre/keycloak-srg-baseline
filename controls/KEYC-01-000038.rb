# -*- encoding : utf-8 -*-
control "KEYC-01-000038" do
  title "Keycloak must be configured to enforce 24 hours as the minimum password lifetime."
  desc  "
    Enforcing a minimum password lifetime helps prevent repeated password changes to defeat the password reuse or history enforcement requirement.
    
    Restricting this setting limits the user's ability to change their password. Passwords need to be changed at specific policy based intervals; however, if the application allows the user to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse.
  "
  desc  "rationale", ""
  desc  "check", "
    If Keyclaok rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. This requirement is not applicable to service account passwords (e.g. shared secrets, pre-shared keys) or the account of last resort.
    
    Where passwords are used, such as temporary or emergency accounts, verify Keyclaok are configured to enforce 24 hours as the minimum password lifetime. When the Keyclaok configuration setting is for \"1 day\", it is required that the length be 24 hours.
    
    If Keyclaok are not configured to enforce 24 hours as the minimum password lifetime, this is a finding.
    
    Keycloak does not inherently provide this functionality. To check that a custom policy is in place to provide this functionality, after logging in with a privileged account, which can be done by running:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    then run the following command:
    
    kcadm.sh get realms/[YOUR REALM] --fields passwordPolicy 
    
    If the command returns with any empty string or null, this is a finding.
    
    If the result does not contain a custom policy that enforce 24 hours as the minimum password lifetime, this is a finding. 
    
    If the result contains an appropriate custom policy, but it does not enforce 24 hours as the minimum password lifetime, this is a finding.
    
  "
  desc  "fix", "
    Configure Keyclaok to enforce 24 hours as the minimum password lifetime. When the Keycloak configuration setting is for \"1 day\", it is required that the length be 24 hours. This requirement is not applicable to service account passwords (e.g. shared secrets, pre-shared keys) or the account of last resort.
    
    Keycloak does not inherently provide this functionality. To create a custom plugin to extend this functionality: navigate to GitHub repo: https://github.com/mitre/keycloak-custom-policies and follow instructions on README.
    
    Then, to configure this settings using the Keycloak admin CLI, do the following from a privileged account:
    First, find the current setting for passwordPolicy: 
    
    kcadm.sh get realms/[YOUR REALM] --fields passwordPolicy
    
    Then, update the password policy corresponding to the current settings with the following line.
    
    kcadm.sh update realms/[YOUR REALM] -s 'passwordPolicy=\"[content from current password policy] and minimumPasswordLife(24)\"'
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000173-AAA-000530"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000038"
  tag cci: ["CCI-000198"]
  tag nist: ["IA-5 (1) (d)"]
end