# -*- encoding : utf-8 -*-
control "KEYC-01-000021" do
  title "Keycloak must be configured to disable non-essential modules."
  desc  "
    It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.
    
    Applications are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 
    
    Examples of non-essential capabilities include, but are not limited to, advertising software or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission, but cannot be disabled.
  "
  desc  "rationale", ""
  desc  "check", "
    Determine if Keyclaok are configured to disable non-essential modules.
    
    If Keyclaok are not configured to disable non-essential modules, this is a finding.
    
    Locate file profile.properties. If such a file is not found, this is a finding. 
    
    Inspect contents in file profile.properties. Unless specified, all features should be disabled as shown below. 
    
    feature.account2=disabled
    feature.account_api=disabled
    feature.admin_fine_grained_authz=disabled
    feature.ciba=disabled
    feature.client_policies=disabled
    feature.client_secret_rotation=disabled
    feature.par=disabled
    feature.declarative_user_profile=disabled
    feature.docker=disabled
    feature.impersonation=disabled
    feature.openshift_integration=disabled
    feature.recovery_codes=disabled
    feature.scripts=disabled
    feature.step_up_authentication=disabled
    feature.token_exchange=disabled
    feature.upload_scripts=disabled
    feature.web_authn=disabled
    feature.update_email=disabled
    
    If a feature is enabled without appropriately specifying so, this is a finding. 
  "
  desc  "fix", "
    Configure Keycloak to disable non-essential modules.
    
    Create or modify file profile.properties. Unless specifically required, disable all features with following lines: 
    
    feature.account2=disabled
    feature.account_api=disabled
    feature.admin_fine_grained_authz=disabled
    feature.ciba=disabled
    feature.client_policies=disabled
    feature.client_secret_rotation=disabled
    feature.par=disabled
    feature.declarative_user_profile=disabled
    feature.docker=disabled
    feature.impersonation=disabled
    feature.openshift_integration=disabled
    feature.recovery_codes=disabled
    feature.scripts=disabled
    feature.step_up_authentication=disabled
    feature.token_exchange=disabled
    feature.upload_scripts=disabled
    feature.web_authn=disabled
    feature.update_email=disabled
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000141-AAA-000670"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000021"
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a"]
end