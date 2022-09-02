# -*- encoding : utf-8 -*-
control "KEYC-01-000039" do
  title "Keycloak must be configured to enforce a 60-day maximum password lifetime restriction."
  desc  "
    Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals. 
    
    One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised. 
    
    This requirement does not include emergency administration accounts that are meant for access to the application in case of failure. These accounts are not required to have maximum password lifetime restrictions.
  "
  desc  "rationale", ""
  desc  "check", "
    If Keycloak rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. This requirement is not applicable to service account passwords (e.g. shared secrets, pre-shared keys) or the account of last resort.
    
    Where passwords are used, such as temporary or emergency accounts, verify Keycloak are configured to enforce a 60-day maximum password lifetime restriction. Additionally, Keycloak must force password change upon the first logon after the expiration of the 60 days.
    
    If Keycloak are not configured to enforce a 60-day maximum password lifetime restriction, this is a finding.
    
    To confirm this setting is configured using the Keycloak admin CLI, after logging in with a privileged account, which can be done by running:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    then run the following command:
    
    kcadm.sh get realms/[YOUR REALM] | grep 'forceExpiredPasswordChange'
    
    If configured correctly, this command should return password policy information.
    If the command returns with any empty string or null, or the returned number is smaller than 60, this is a finding.
  "
  desc  "fix", "
    Configure Keycloak to enforce a 60-day maximum password lifetime restriction. Additionally, configure Keycloak to force password change upon the first logon after the expiration of the 60 days. This requirement is not applicable to service account passwords (e.g. shared secrets, pre-shared keys) or the account of last resort.
    
    To configure this settings using the Keycloak admin CLI, do the following from a privileged account:
    First, find the current setting for expiring passwords: 
    
    kcadm.sh get realms/[YOUR REALM] | grep 'forceExpiredPasswordChange'
    
    Next, concatenate the string 'forceExpiredPasswordChange(60)' to the current setting or update the setting if it is already set. If there is no password policy set, you can set it for the first time using the same process.
    Finally, update the password policy in corresponding to the current settings with requirement of expiration in 60 days
    
    kcadm.sh update realms/[YOUR REALM] -s 'passwordPolicy=\"[content from current password policy] and forceExpiredPasswordChange(60)\"'
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000174-AAA-000540"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000039"
  tag cci: ["CCI-000199"]
  tag nist: ["IA-5 (1) (d)"]
end