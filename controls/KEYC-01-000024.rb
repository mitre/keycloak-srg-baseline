# -*- encoding : utf-8 -*-
control "KEYC-01-000024" do
  title "Keycloak must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments."
  desc  "
    In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.
    
    Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services; however, doing so increases risk over limiting the services provided by any one component. 
    
    To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the Keycloak configuration to ascertain if it prohibits or restricts the use of organization-defined functions, ports, protocols, and/or services. Further determine if the use is as defined in the PPSM CAL and vulnerability assessments.
    
    If Keycloak are not configured in accordance with the PPSM CAL and vulnerability assessments, this is a finding.
    
    Check which services are currently active with the following command:
    
    # firewall-cmd --list-all
    public (default, active)
      interfaces:
      sources: 
      services: dhcpv6-client dns http https ldaps rpc-bind ssh
      ports: 
      masquerade: no
      forward-ports: 
      icmp-blocks: 
      rich rules: 
    
    Ask the System Administrator for the site or program PPSM CLSA. Verify the services allowed by the firewall match the PPSM CLSA. 
    
    If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM Category Assurance List (CAL), this is a finding.
    
    Check keycloak configuration file, keycloak.conf. If any of the following services are used, but the file does not contain the following key-value pairs, it is a finding. 
    
    db-url-port=[APPROPRIATE DB URL PORT]
    hostname-port=[APPROPRIATE HOSTNAME PORT]
    http-port=[APPROPRIATE HTTP PORT]
    https-port=[APPROPRIATE HTTPS PORT]
    log-gelf-port=[APPROPRIATE GELF PORT]
  "
  desc  "fix", "
    Configure Keycloak to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.
    
    Update the host's firewall settings and/or running services to comply with the PPSM CLSA for the site or program and the PPSM CAL.
    
    Create or update Keycloak logging handlers with the following lines in your keycloak configuration file, conf/keycloak.conf:
    
    db-url-port=[APPROPRIATE DB URL PORT]
    hostname-port=[APPROPRIATE HOSTNAME PORT]
    http-port=8080 [OR APPROPRIATE HTTP PORT]
    https-port=8443 [OR APPROPRIATE HTTPS PORT]
    log-gelf-port=[APPROPRIATE GELF PORT]
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000142-AAA-000680"
  tag gid: nil
  tag rid: nil
  tag stig_id: "KEYC-01-000024"
  tag cci: ["CCI-000382"]
  tag nist: ["CM-7 b"]
end