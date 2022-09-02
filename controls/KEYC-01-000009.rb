# -*- encoding : utf-8 -*-
control "KEYC-01-000009" do
  title "Keycloak must be configured to automatically lock user accounts after three consecutive invalid logon attempts within a 15-minute time period."
  desc  "By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account."
  desc  "rationale", ""
  desc  "check", "
    If Keycloak relies on directory services for user account management, this control is not applicable, as the connected directory services must perform this function.
    
    Verify Keycloak is configured to automatically lock user accounts after three consecutive invalid logon attempts within a 15-minute time period.
    
    If Keycloak is not configured to automatically lock user accounts after three consecutive invalid logon attempts within a 15-minute time period, this is a finding.
    
    To confirm this setting is configured, log into the Keycloak admin CLI with a privileged account:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    then run the following command:
    
    kcadm.sh get realms/[YOUR REALM] | grep 'bruteForceProtected'
    kcadm.sh get realms/[YOUR REALM] | grep 'failureFactor'
    kcadm.sh get realms/[YOUR REALM] | grep 'maxDeltaTimeSeconds'
    
    If the results are not as follows, then this is a finding.
    
    \"bruteForceProtected\" : true
    \"failureFactor\" : 3
    \"maxDeltaTimeSeconds\" : 900
    
  "
  desc  "fix", "
    Configure Keycloak to automatically lock user accounts after three consecutive invalid logon attempts within a 15-minute time period.
    
    To configure this settings using the Keycloak admin CLI, do the following from a privileged account:
    First, find the current setting for upperCase: 
    
    kcadm.sh get realms/[YOUR REALM] | grep 'bruteForceProtected'
    kcadm.sh get realms/[YOUR REALM] | grep 'failureFactor'
    kcadm.sh get realms/[YOUR REALM] | grep 'maxDeltaTimeSeconds'
    
    Next, configure the settings 'bruteForceProtected', 'failureFactor' and 'maxDeltaTimeSeconds' or update the setting if it is already set. You can set it for the first time using the same process.
    
    kcadm.sh update realms/[YOUR REALM] -s 'bruteForceProtected=true'
    kcadm.sh update realms/[YOUR REALM] -s 'failureFactor=3'
    kcadm.sh update realms/[YOUR REALM] -s 'maxDeltaTimeSeconds=900'
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000065-AAA-000200"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000009"
  tag cci: ["CCI-000044"]
  tag nist: ["AC-7 a"]
end