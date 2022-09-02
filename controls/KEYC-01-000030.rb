# -*- encoding : utf-8 -*-
control "KEYC-01-000030" do
  title "Keycloak must be configured to prohibit password reuse for a minimum of five generations."
  desc  "
    Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
    
    To meet password policy requirements, passwords need to be changed at specific policy-based intervals. 
    
    If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.
  "
  desc  "rationale", ""
  desc  "check", "
    If Keycloak rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. This requirement is not applicable to service account passwords (e.g. shared secrets, pre-shared keys) or the account of last resort.
    
    Where passwords are used, such as temporary or emergency accounts, verify Keycloak are configured to prohibit password reuse for a minimum of five generations. This requirement may be verified by demonstration or configuration review. 
    
    If Keycloak are not configured to prohibit password reuse for a minimum of five generations, this is a finding.
    
    To confirm this setting is configured using the Keycloak admin CLI, after logging in with a privileged account, which can be done by running:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    then run the following command:
    
    kcadm.sh get realms/[YOUR REALM] | grep 'passwordHistory(5)'
    
    If configured correctly, this command should return password policy information.
    If the command returns with any empty string or null, this is a finding.
  "
  desc  "fix", "
    Configure Keycloak to prohibit password reuse for a minimum of five generations. This requirement is not applicable to service account passwords (e.g. shared secrets, pre-shared keys) or the account of last resort.
    
    To configure this settings using the Keycloak admin CLI, do the following from a privileged account:
    First, find the current setting for passwordHistory: 
    
    kcadm.sh get realms/[YOUR REALM] | grep 'passwordPolicy'
    
    Next, concatenate the string 'passwordHistory(5)' to the current setting or update the password history if it is already set. If there is no password policy set, you can set it for the first time using the same process.
    Finally, update the password policy in corresponding to the current settings with the password history setting configured to 5.
    
    kcadm.sh update realms/[YOUR REALM] -s 'passwordPolicy=\"[content from current password policy] and passwordHistory(5)\"'
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000165-AAA-000550"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000030"
  tag cci: ["CCI-000200"]
  tag nist: ["IA-5 (1) (e)"]
end