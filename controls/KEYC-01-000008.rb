# -*- encoding : utf-8 -*-
control "KEYC-01-000008" do
  title "Keycloak must be configured to automatically audit account removal actions."
  desc  "When application accounts are removed, user accessibility is affected. Once an attacker establishes access to an application, the attacker often attempts to remove authorized accounts to disrupt services or prevent the implementation of countermeasures. Auditing account removal actions provides logging that can be used for forensic purposes."
  desc  "rationale", ""
  desc  "check", "
    If Keycloak relies on directory services for user account management, this is not applicable and the connected directory services must perform this function. 
    
    Verify Keycloak is configured to automatically audit account removal actions.
    
    If Keycloak is not configured to automatically audit account removal actions, this is a finding.
    
    To check if Keycloak is configured to audit account account removal actions, log into the Keycloak admin CLI with a privileged account:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    Then run the following command: 
    
    kcadm.sh get events/config -r [YOUR REALM] 
    
    If the results are not as follows, then it is a finding.
    
    \"eventsEnabled\" : true, 
    \"eventsListeners\" : [ \"jboss-logging\" ],
    \"enabledEventTypes\" : [ list with DELETE concatenated ]
    \"adminEventsEnabled\" : true,
    \"adminEventsDetailsEnabled\" : true
    
    Note: Enabling 'events', 'adminEvents' and 'adminEventsDetails', along with configuring 'eventsListeners' and 'enabledEventTypes',  configures Keycloak to audit login events, account creations, account updates, account deletions, and admin actions.
    
  "
  desc  "fix", "
    Configure Keycloak to automatically audit account removal actions.
    
    To configure this setting using the Keycloak admin CLI, do the following from a privileged account:
    
    First, find the current enabled event types: 
    
    kcadm.sh get events/config -r [your realm] | grep enabledEventTypes 
    
    Then update the configuration: 
    
    kcadm.sh update events/config -r [your realm] -s adminEventsEnabled=true -s adminEventsDetailsEnabled=true -s eventsEnabled=true -s eventsListeners=[\"jboss-logging\"] -s enabledEventTypes=\"[full list with DELETE concatenated]\"
    
    Note: Enabling 'events', 'adminEvents' and 'adminEventsDetails', along with configuring 'eventsListeners' and 'enabledEventTypes',  configures Keycloak to audit login events, account creations, account updates, account deletions, and admin actions.
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000029-AAA-000120"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000008"
  tag cci: ["CCI-001405"]
  tag nist: ["AC-2 (4)"]


end