# -*- encoding : utf-8 -*-
control "KEYC-01-000027" do
  title "Keycloak must be configured to require multifactor authentication using Common Access Card (CAC) Personal Identity Verification (PIV) credentials for authenticating non-privileged user accounts."
  desc  "
    To assure accountability and prevent unauthenticated access, non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system. 
    
    Multifactor authentication uses two or more factors to achieve authentication. 
    
    Factors include:
    (i) Something you know (e.g., password/PIN); 
    (ii) Something you have (e.g., cryptographic identification device, token); or 
    (iii) Something you are (e.g., biometric). 
    
    A non-privileged account is any information system account with authorizations of a non-privileged user. 
    
    Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.
    
    Applications integrating with the DoD Active Directory and using the DoD CAC are examples of compliant multifactor authentication solutions.
  "
  desc  "rationale", ""
  desc  "check", "
    Verify Keycloak are configured to require multifactor authentication using CAC PIV credentials for authenticating non-privileged user accounts.
    
    If Keycloak are not configured to require multifactor authentication using CAC PIV credentials for authenticating non-privileged user accounts, this is a finding.
    
    To confirm this setting is configured using the Keycloak admin CLI, after logging in with a privileged account, which can be done by running:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    then run the following command:
    
    kcadm.sh get authentication/flows -r [YOUR REALM] 
    
    Then list executions for browser flows (including default and custom browser flows): 
    
    kcadm.sh get authentication/flows/[FLOW_ALIAS]/executions -r [YOUR REALM] 
    
    If the result does not contain any executions containing the following key-value pair, it is a finding.
    
    \"providerId\" : \"auth-x509-client-username-form\"
    
    Then check whether this authentication method is required for authenticating non-privileged user accounts. 
    
    Inspect when execution with providerId \"auth-x509-client-username-form\" is executed by checking conditional executions on the same level. 
    
    If there does not exist any executions on the same level with any of following providerId, this is a finding: 
    \"conditional-user-attribute\"
    
    OR 
    \"conditional-level-authentication\"
    
    OR 
    \"conditional-user-configured\"
    
    OR
    \"conditional-user-attribute\"
    
    If the conditional executions are not configured to execute when authenticating non-privileged user accounts, this is a finding. 
  "
  desc  "fix", "
    Configure Keycloak to require multifactor authentication using CAC PIV credentials for authenticating non-privileged user accounts.
    
    Navigate on GUI to appropriate realms. Navigate to 'Authentication' tab. Select 'Flows' tab, then duplicate the 'Browser' authentication flow and give the copied flow an appropriate name, [FLOW NAME].
    
    Add execution with providers \"Condition - User Role\" within the subflow \"[FLOW NAME] Browser - Conditional OTP\". Mark 'Condition - User Role' as REQUIRED, configure its config with updates on appropriate \"Alias\" and appropriate \"User Role\". Mark execution \"OTP Form\" as REQUIRED within the same subflow. 
    
    Add a subflow on the same level as \"[FLOW NAME] Browser - Conditional OTP\" and name it appropriately as \"Browser - Conditional CAC\". Mark \"Browser - Conditional CAC\" as CONDITIONAL. Within the subflow \"Browser - Conditional CAC\", add two execution with providers \"Condition - User Role\" and \"X509/Validate Username Form\", respectively. Mark 'Condition - User Role' as REQUIRED, configure its config with updates on appropriate \"Alias\" and appropriate \"User Role\". Mark 'X509/Validate Username Form' as REQUIRED, configure its config with updates on appropriate \"Alias\" and rest of appropriate settings. 
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000150-AAA-000410"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000027"
  tag cci: ["CCI-000766"]
  tag nist: ["IA-2 (2)"]
end