# -*- encoding : utf-8 -*-
control "KEYC-01-000010" do
  title "Keycloak must be configured to audit each authentication and authorization transaction."
  desc  "
    Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 
    
    Audit records can be generated from various components within the application (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.
    
    DoD has defined the list of events for which the application will provide an audit record generation capability as the following: 
    
    (i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);
    (ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and
    (iii) All account creation, modification, disabling, and termination actions.
  "
  desc  "rationale", ""
  desc  "check", "
    Verify Keycloak is to audit each authentication and authorization transaction.
    
    If Keycloak is not configured to audit each authentication and authorization transaction, this is a finding.
    
    To check if Keycloak is configured to audit this setting, log into the Keycloak admin CLI with a privileged account:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    Then run the following command: 
    
    kcadm.sh get events/config -r [YOUR REALM] 
    
    If the results are not as follows, then it is a finding.
    
    \"eventsEnabled\" : true, 
    \"eventsListeners\" : [ \"jboss-logging\" ],
    \"enabledEventTypes\" : [ APPROPRIATE EVENT TYPES ]
    \"adminEventsEnabled\" : true,
    \"adminEventsDetailsEnabled\" : true
    
    Note: Enabling 'events', 'adminEvents' and 'adminEventsDetails', along with configuring 'eventsListeners' and 'enabledEventTypes',  configures Keycloak to audit login events, account creations, account updates, account deletions, and admin actions.
  "
  desc  "fix", "
    Configure Keycloak to audit each authentication and authorization transaction.
    
    To configure this setting using the Keycloak admin CLI, do the following from a privileged account:
    
    First, find the current enabled event types: 
    
    kcadm.sh get events/config -r [your realm] | grep enabledEventTypes 
    
    Then update the configuration: 
    
    kcadm.sh update events/config -r [your realm] -s eventsEnabled=true -s 'eventsListeners=[\"jboss-logging\"] -s adminEventsEnabled=true -s adminEventsDetailsEnabled=true -s enabledEventTypes=\"[ APPROPRIATE EVENT TYPES ]\"
    
    Note: Enabling 'events', 'adminEvents' and 'adminEventsDetails', along with configuring 'eventsListeners' and 'enabledEventTypes',  configures Keycloak to audit login events, account creations, account updates, account deletions, and admin actions.
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000089-AAA-000380"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000010"
  tag cci: ["CCI-000169"]
  tag nist: ["AU-12 a"]
end