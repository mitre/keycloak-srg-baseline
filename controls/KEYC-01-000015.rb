# -*- encoding : utf-8 -*-
control "KEYC-01-000015" do
  title "Keycloak configuration audit records must identify the outcome of the events."
  desc  "
    Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.
    
    Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the information system after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.
  "
  desc  "rationale", ""
  desc  "check", "
    Verify Keycloak configuration audit records identify the outcome of the events.
    
    If Keycloak configuration audit records do not identify the outcome of the events, this is a finding.
    
    To confirm this setting is configured using the Keycloak admin CLI, after logging in with a privileged account, which can be done by running:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    then run the following command:
    
    kcadm.sh get events/config -r [YOUR REALM] 
    
    If the results are not as follows, then it is a finding.
    
    \"eventsEnabled\" : true, 
    \"eventsListeners\" : [ \"jboss-logging\" ],
    \"enabledEventTypes\" : [ APPROPRIATE EVENT TYPES ],
    \"adminEventsEnabled\" : true,
    \"adminEventsDetailsEnabled\" : true
    
    Then run the command: 
    
    kcadm.sh get events -r [YOUR REALM]
    
    If the individual event from the resulting event lists does not contain the following key-value pair, then it is a finding. 
    
    \"type\" : [Type/Outcome of the event]
  "
  desc  "fix", "
    Configure Keycloak configuration audit records to identify the outcome of the events.
    
    To configure this setting using the Keycloak admin CLI, do the following from a privileged account:
    
    kcadm.sh update events/config -r [your realm] -s eventsEnabled=true -s eventsListeners=[\"jboss-logging\"] -s adminEventsEnabled=true -s adminEventsDetailsEnabled=true
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000099-AAA-000260"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000015"
  tag cci: ["CCI-000134"]
  tag nist: ["AU-3"]
end