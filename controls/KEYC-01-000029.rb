# -*- encoding : utf-8 -*-
control "KEYC-01-000029" do
  title "Keycloak must be configured to enforce a minimum 15-character password length."
  desc  "Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password."
  desc  "rationale", ""
  desc  "check", "
    If Keycloak rely on directory services for user account management, this is not applicable and the connected directory services must perform this function.
    
    Where passwords (to include randomly assigned passwords, shared secrets, and pre-shared keys) are used, verify Keycloak are configured to enforce a minimum 15-character password length. This requirement may be verified by demonstration or configuration review.
    
    If Keycloak are not configured to enforce a minimum 15-character password length, this is a finding.
    
    To confirm this setting is configured using the Keycloak admin CLI, after logging in with a privileged account, which can be done by running:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    then run the following command:
    
    kcadm.sh get realms/[YOUR REALM] | grep 'length(15)'
    
    If configured correctly, this command should return password policy information.
    If the command returns with any empty string or null, this is a finding.
  "
  desc  "fix", "
    Configure Keycloak to enforce a minimum 15-character password length. This includes randomly assigned passwords, shared secrets, and pre-shared keys.
    
    To configure this settings using the Keycloak admin CLI, do the following from a privileged account:
    First, find the current setting for password length: 
    
    kcadm.sh get realms/[YOUR REALM] | grep 'length(15)'
    
    Next, concatenate the string 'length(15)' to the current setting or update the length setting if it is already set. If there is no password policy set, you can set it for the first time using the same process.
    Finally, update the password policy in corresponding to the current settings with requirement of password length at least 15.
    
    kcadm.sh update realms/[YOUR REALM] -s 'passwordPolicy=\"[content from current password policy] and length(15)\"'
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000164-AAA-000450"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000029"
  tag cci: ["CCI-000205"]
  tag nist: ["IA-5 (1) (a)"]
end