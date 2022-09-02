# -*- encoding : utf-8 -*-
control "KEYC-01-000007" do
  title "Keycloak must be configured to automatically audit account disabling actions."
  desc  "When application accounts are disabled, user accessibility is affected. Once an attacker establishes access to an application, the attacker often attempts to disable authorized accounts to disrupt services or prevent the implementation of countermeasures. Auditing account disabling actions provides logging that can be used for forensic purposes."
  desc  "rationale", ""
  desc  "check", "
    If Keycloak relies on directory services for user account management, this is not applicable and the connected directory services must perform this function. 
    
    Verify Keycloak is configured to automatically audit account disabling actions.
    
    If Keycloak is not configured to automatically audit account disabling actions, this is a finding.
    
    To check if Keycloak is configured to audit account disabling actions, log into the Keycloak admin CLI with a privileged account:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    Then run the following commands:
    
    kcadm.sh get events/config -r [your realm]
    
    If the results are not as follows, then it is a finding.
    
    \"eventsListeners\" : [ \"jboss-logging\" ],
    \"adminEventsEnabled\" : true,
    \"adminEventsDetailsEnabled\" : true
    
    Note: Enabling 'adminEvents' and 'adminEventsDetails', along with configuring 'eventsListeners', configures Keycloak to audit account creations, account updates, account deletions, and admin actions.
  "
  desc  "fix", "
    Configure Keycloak to automatically audit account disabling actions.
    
    To configure this setting using the Keycloak admin CLI, do the following from a privileged account:
    
    kcadm.sh update events/config -r [your realm] -s adminEventsEnabled=true -s adminEventsDetailsEnabled=true -s eventsListeners=[\"jboss-logging\"]
    
    Note: Enabling 'adminEvents' and 'adminEventsDetails', along with configuring 'eventsListeners', configures Keycloak to audit account creations, account updates, account deletions, and admin actions.
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000028-AAA-000110"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000007"
  tag cci: ["CCI-001404"]
  tag nist: ["AC-2 (4)"]

  eventsListeners = '"eventsListeners" : [ "jboss-logging" ]'
  adminEventsEnabled = '"adminEventsEnabled" : true'
  adminEventsDetailsEnabled = '"adminEventsDetailsEnabled" : true'

  describe command('/opt/keycloak/bin/kcadm.sh get events/config -r demo') do
    its('stdout') { should include eventsListeners }
    its('stdout') { should include adminEventsEnabled }
    its('stdout') { should include adminEventsDetailsEnabled }
  end
end