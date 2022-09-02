# -*- encoding : utf-8 -*-
control "KEYC-01-000049" do
  title "Keycloak must be configured to notify the system administrators and ISSO for account disabling actions."
  desc  "
    When application accounts are disabled, user accessibility is affected. Accounts are utilized for identifying individual users or for identifying the application processes themselves. Sending notification of account disabling events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes.
    
    Keycloak may not have built-in capabilities to notify the administrators and ISSO and may require the use of third-party tools (e.g. SNMP, SIEM) to perform the notification.
  "
  desc  "rationale", ""
  desc  "check", "
    If Keycloak relies on directory services for user account management, this is not applicable and the connected directory services must perform this function. 
    
    Verify Keycloak is configured to notify the system administrators and ISSO for account disabling actions.
    
    If Keyclaok is not configured to notify the system administrators and ISSO for account disabling actions, this is a finding.
    
    Keycloak does not inherently provide this functionality. To check that a custom policy is in place to provide this functionality, after logging in with a privileged account, which can be done by running:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    then run the following command:
    
    kcadm.sh get realms | grep 'event'
    
    If the results are not as follows, then it is a finding.
    
    \"eventsEnabled\" : true,
    \"eventsListeners\" : [ CUSTOM EVENT LISTENERS ]
    
    Note: Keycloak does not inherently provide the functionality of notifying administrators and ISSO on account events. There needs to be a custom policy to implement this functionality.
  "
  desc  "fix", "
    Configure Keycloak to notify system administrators and ISSO for account disabling actions.
    
    Keycloak does not inherently provide this functionality. To create a custom plugin to extend this functionality: navigate to GitHub repo: https://github.com/mitre/keycloak-custom-policies and follow instructions on README.
    
    Note: Keycloak does not inherently provide the functionality of notifying administrators and ISSO on account events. There needs to be a custom policy to implement this functionality.
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000293-AAA-000150"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000049"
  tag cci: ["CCI-001685"]
  tag nist: ["AC-2 (4)"]
end