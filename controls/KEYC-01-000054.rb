# -*- encoding : utf-8 -*-
control "KEYC-01-000054" do
  title "Keycloak must be configured to maintain locks on user accounts until released by an administrator."
  desc  "By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account."
  desc  "rationale", ""
  desc  "check", "
    If Keycloak rely on directory services for user account management, this is not applicable and the connected directory services must perform this function.
    
    Verify Keycloak are configured to maintain locks on user accounts until released by an administrator.
    
    If Keycloak are not configured to maintain locks on user accounts until released by an administrator, this is a finding.
    
    To confirm this setting is configured using the Keycloak admin CLI, after logging in with a privileged account, which can be done by running:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    then run the following command:
    
    kcadm.sh get realms/[YOUR REALM] | grep 'bruteForceProtected'
    kcadm.sh get realms/[YOUR REALM] | grep 'permanentLockout'
    kcadm.sh get realms/[YOUR REALM] | grep 'failureFactor'
    
    If configured correctly, this command should return password policy information, with bruteForceProtected and permanentLockout set to \"true\", and failureFactor set to a number.
    If the command returns with any empty string or null, or if bruteForceProtected and permanentLockout are not set to \"true\", this is a finding.
  "
  desc  "fix", "
    Configure Keycloak to maintain locks on user accounts until released by an administrator.
    
    To configure this settings using the Keycloak admin CLI, do the following from a privileged account:
    First, find the current setting: 
    
    kcadm.sh get realms/[YOUR REALM] | grep 'bruteForceProtected'
    kcadm.sh get realms/[YOUR REALM] | grep 'permanentLockout'
    kcadm.sh get realms/[YOUR REALM] | grep 'failureFactor'
    
    Next, configure the settings 'bruteForceProtected', 'permanentLockout', 'failureFactor' or update the setting if it is already set. You can set it for the first time using the same process.
    
    kcadm.sh update realms/[YOUR REALM] -s 'bruteForceProtected=\"true\"'
    kcadm.sh update realms/[YOUR REALM] -s 'permanentLockout=\"true\"'
    kcadm.sh update realms/[YOUR REALM] -s 'failureFactor=\"30\"'
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000345-AAA-000210"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000054"
  tag cci: ["CCI-002238"]
  tag nist: ["AC-7 b"]
end