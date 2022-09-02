# -*- encoding : utf-8 -*-
control "KEYC-01-000050" do
  title "Keycloak must be configured to notify the system administrators and ISSO for account removal actions."
  desc  "
    When application accounts are removed, user accessibility is affected. Accounts are utilized for identifying users or for identifying the application processes themselves. Sending notification of account removal events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes.
    
    Keycloak may not have built-in capabilities to notify system administrators and ISSO and may require the use of third-party tools (e.g. SNMP, SIEM) to perform the notification.
  "
  desc  "rationale", ""
  desc  "check", "
    If Keycloak rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. 
    
    Verify Keycloak are configured to notify the system administrators and ISSO for account removal actions.
    
    If Keycloak are not configured to notify the system administrators and ISSO for account removal actions, this is a finding.
    
    Keycloak does not inherently provide this functionality. To check that a custom policy is in place to provide this functionality, after logging in with a privileged account, which can be done by running:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    then run the following command:
    
    kcadm.sh get realms | grep 'event'
    
    If the results are not as follows, then it is a finding.
    
    \"eventsEnabled\" : true,
    \"eventsListeners\" : [ CUSTOM EVENT LISTENERS ]
  "
  desc  "fix", "
    Configure Keycloak to notify system administrators and ISSO for account removal actions.
    
    Keycloak does not inherently provide this functionality. To create a custom plugin to extend this functionality: navigate to GitHub repo: https://github.com/mitre/keycloak-event-listener-email and follow instructions on README.
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000294-AAA-000160"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000050"
  tag cci: ["CCI-001686"]
  tag nist: ["AC-2 (4)"]
end