# -*- encoding : utf-8 -*-
control "KEYC-01-000026" do
  title "Keycloak must be configured to require multifactor authentication using Personal Identity Verification (PIV) credentials for authenticating privileged user accounts."
  desc  "
    Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. 
    
    Multifactor authentication requires using two or more factors to achieve authentication. 
    
    Factors include: 
    (i) something a user knows (e.g., password/PIN); 
    (ii) something a user has (e.g., cryptographic identification device, token); or 
    (iii) something a user is (e.g., biometric). 
    
    A privileged account is defined as an information system account with authorizations of a privileged user. 
    
    Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the Internet).
  "
  desc  "rationale", ""
  desc  "check", "
    Verify Keycloak are configured to require multifactor authentication using PIV credentials for authenticating privileged user accounts. Although the Common Access Card (CAC) is a PIV credential, it should not be used for privileged accounts, but rather only for non-privileged accounts. Administrative smart cards and tokens, separate from the CAC, are the preferred solution for privileged accounts.
    
    If Keycloak are not configured to require multifactor authentication using PIV credentials for authenticating privileged user accounts, this is a finding.
    
    To confirm this setting is configured using the Keycloak admin CLI, after logging in with a privileged account, which can be done by running:
    
    kcadm.sh config credentials --server [server location] --realm master --user [username] --password [password]
    
    then run the following command:
    
    kcadm.sh get authentication/flows -r [YOUR REALM] 
    
    Then list executions for browser flows (including default and custom browser flows): 
    
    kcadm.sh get authentication/flows/[FLOW_ALIAS]/executions -r [YOUR REALM] 
    
    If the result does not contain any executions containing the following key-value pair, it is a finding.
    
    \"providerId\" : \"auth-otp-form\"
    
    Then check whether this authentication method is required for authenticating privileged user accounts. 
    
    Inspect when execution with providerId \"auth-otp-form\" is executed by checking conditional executions on the same level. 
    
    If there does not exist any executions on the same level with any of following providerId, this is a finding: 
    \"conditional-user-attribute\"
    
    OR 
    \"conditional-level-authentication\"
    
    OR 
    \"conditional-user-configured\"
    
    OR
    \"conditional-user-attribute\"
    
    If the conditional executions are not configured to execute when authenticating privileged user accounts, this is a finding. 
  "
  desc  "fix", "
    Configure Keycloak to require multifactor authentication using PIV credentials for authenticating privileged user accounts. Although the CAC is a PIV credential, it should not be used for privileged accounts, but rather only for non-privileged accounts.
    
    Navigate on GUI to appropriate realms. Navigate to 'Authentication' tab. Select 'Flows' tab, then duplicate the 'Browser' authentication flow and give the copied flow an appropriate name, [FLOW NAME].
    
    Add execution with providers \"Condition - User Role\" within the subflow \"[FLOW NAME] Browser - Conditional OTP\". Mark 'Condition - User Role' as REQUIRED, configure its config with updates on appropriate \"Alias\" and appropriate \"User Role\". Mark execution \"OTP Form\" as REQUIRED within the same subflow. 
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000149-AAA-000400"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000026"
  tag cci: ["CCI-000765"]
  tag nist: ["IA-2 (1)"]
end