const fs = require('fs');

const controls = [
  {
    group: "1. Inventory and Control of Enterprise Assets",
    safeguards: [
      "Establish and Maintain Detailed Enterprise Asset Inventory",
      "Address Unauthorized Assets",
      "Utilize an Active Discovery Tool",
      "Use Dynamic Host Configuration Protocol (DHCP) Logging to Update Enterprise Asset Inventory",
      "Use a Passive Asset Discovery Tool"
    ]
  },
  {
    group: "2. Inventory and Control of Software Assets",
    safeguards: [
      "Establish and Maintain a Software Inventory",
      "Ensure Authorized Software is Currently Supported",
      "Address Unauthorized Software",
      "Utilize Automated Software Inventory Tools",
      "Allowlist Authorized Software",
      "Allowlist Authorized Libraries",
      "Allowlist Authorized Scripts"
    ]
  },
  {
    group: "3. Data Protection",
    safeguards: [
      "Establish and Maintain a Data Management Process",
      "Establish and Maintain a Data Inventory",
      "Configure Data Access Control Lists",
      "Enforce Data Retention",
      "Securely Dispose of Data",
      "Encrypt Data on End-User Devices",
      "Establish and Maintain a Data Classification Scheme",
      "Document Data Flows",
      "Encrypt Data on Removable Media",
      "Encrypt Sensitive Data in Transit",
      "Encrypt Sensitive Data at Rest",
      "Segment Data Processing and Storage Based on Sensitivity",
      "Deploy a Data Loss Prevention Solution",
      "Log Sensitive Data Access"
    ]
  },
  {
    group: "4. Secure Configuration of Enterprise Assets and Software",
    safeguards: [
      "Establish and Maintain a Secure Configuration Process",
      "Establish and Maintain a Secure Configuration Process for Network Infrastructure",
      "Configure Automatic Session Locking on Enterprise Assets",
      "Implement and Manage a Firewall on Servers",
      "Implement and Manage a Firewall on End-User Devices",
      "Securely Manage Enterprise Assets and Software",
      "Manage Default Accounts on Enterprise Assets and Software",
      "Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
      "Configure Trusted DNS Servers on Enterprise Assets",
      "Enforce Automatic Device Lockout on Portable End-User Devices",
      "Enforce Remote Wipe Capability on Portable End-User Devices",
      "Separate Enterprise Workspaces on Mobile End-User Devices"
    ]
  },
  {
    group: "5. Account Management",
    safeguards: [
      "Establish and Maintain an Inventory of Accounts",
      "Use Unique Passwords",
      "Disable Dormant Accounts",
      "Restrict Administrator Privileges to Dedicated Administrator Accounts",
      "Establish and Maintain an Inventory of Service Accounts",
      "Centralize Account Management"
    ]
  },
  {
    group: "6. Access Control Management",
    safeguards: [
      "Establish an Access Granting Process",
      "Establish an Access Revoking Process",
      "Require MFA for Externally-Exposed Applications",
      "Require MFA for Remote Network Access",
      "Require MFA for Administrative Access",
      "Establish and Maintain an Inventory of Authentication and Authorization Systems",
      "Centralize Access Control",
      "Define and Maintain Role-Based Access Control"
    ]
  },
  {
    group: "7. Continuous Vulnerability Management",
    safeguards: [
      "Establish and Maintain a Vulnerability Management Process",
      "Establish and Maintain a Remediation Process",
      "Perform Automated Operating System Patch Management",
      "Perform Automated Application Patch Management",
      "Perform Automated Vulnerability Scans of Internal Enterprise Assets",
      "Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets",
      "Remediate Detected Vulnerabilities"
    ]
  },
  {
    group: "8. Audit Log Management",
    safeguards: [
      "Establish and Maintain an Audit Log Management Process",
      "Collect Audit Logs",
      "Ensure Adequate Audit Log Storage",
      "Standardize Time Synchronization",
      "Collect Detailed Audit Logs",
      "Collect DNS Query Audit Logs",
      "Collect URL Request Audit Logs",
      "Collect Command-Line Audit Logs",
      "Centralize Audit Logs",
      "Retain Audit Logs",
      "Conduct Audit Log Reviews",
      "Collect Service Provider Logs"
    ]
  },
  {
    group: "9. Email and Web Browser Protections",
    safeguards: [
      "Ensure Use of Only Fully Supported Browsers and Email Clients",
      "Use DNS Filtering Services",
      "Maintain and Enforce Network-Based URL Filters",
      "Restrict Unnecessary or Unauthorized Browser and Email Client Extensions",
      "Implement DMARC",
      "Block Unnecessary File Types",
      "Deploy and Maintain Email Server Anti-Malware Protections"
    ]
  },
  {
    group: "10. Malware Defenses",
    safeguards: [
      "Deploy and Maintain Anti-Malware Software",
      "Configure Automatic Anti-Malware Signature Updates",
      "Disable Autorun and Autoplay for Removable Media",
      "Configure Automatic Anti-Malware Scanning of Removable Media",
      "Enable Anti-Exploitation Features",
      "Centrally Manage Anti-Malware Software",
      "Use Behavior-Based Anti-Malware Software"
    ]
  },
  {
    group: "11. Data Recovery",
    safeguards: [
      "Establish and Maintain a Data Recovery Process",
      "Perform Automated Backups",
      "Protect Recovery Data",
      "Establish and Maintain an Isolated Instance of Recovery Data",
      "Test Data Recovery"
    ]
  },
  {
    group: "12. Network Infrastructure Management",
    safeguards: [
      "Ensure Network Infrastructure is Up-to-Date",
      "Establish and Maintain a Secure Network Architecture",
      "Securely Manage Network Infrastructure",
      "Establish and Maintain Architecture Diagrams",
      "Centralize Network Authentication, Authorization, and Auditing (AAA)",
      "Use of Secure Network Management and Communication Protocols",
      "Ensure Remote Devices Utilize a VPN and are Connecting to an Enterprise's AAA Infrastructure",
      "Establish and Maintain Dedicated Computing Resources for All Administrative Work"
    ]
  },
  {
    group: "13. Network Monitoring and Defense",
    safeguards: [
      "Centralize Security Event Alerting",
      "Deploy a Host-Based Intrusion Detection Solution",
      "Deploy a Network Intrusion Detection Solution",
      "Perform Traffic Filtering Between Network Segments",
      "Manage Access Control for Remote Assets",
      "Collect Network Traffic Flow Logs",
      "Deploy a Host-Based Intrusion Prevention Solution",
      "Deploy a Network Intrusion Prevention Solution",
      "Deploy Port-Level Access Control",
      "Perform Application Layer Filtering",
      "Tune Security Event Alerting Thresholds"
    ]
  },
  {
    group: "14. Security Awareness and Skills Training",
    safeguards: [
      "Establish and Maintain a Security Awareness Program",
      "Train Workforce Members to Recognize Social Engineering Attacks",
      "Train Workforce Members on Authentication Best Practices",
      "Train Workforce on Data Handling Best Practices",
      "Train Workforce Members on Causes of Unintentional Data Exposure",
      "Train Workforce Members on Recognizing and Reporting Security Incidents",
      "Train Workforce on How to Identify and Report if Their Enterprise Assets are Missing Security Updates",
      "Train Workforce on the Dangers of Connecting to and Transmitting Data Over Insecure Networks",
      "Conduct Security Awareness and Skills Training on Recognizing and Reporting Security Incidents"
    ]
  },
  {
    group: "15. Service Provider Management",
    safeguards: [
      "Establish and Maintain an Inventory of Service Providers",
      "Establish and Maintain a Service Provider Management Policy",
      "Classify Service Providers",
      "Ensure Service Provider Contracts Include Security Requirements",
      "Assess Service Providers",
      "Monitor Service Providers",
      "Securely Decommission Service Providers"
    ]
  },
  {
    group: "16. Application Software Security",
    safeguards: [
      "Establish and Maintain a Secure Application Development Process",
      "Establish and Maintain a Process to Accept and Address Software Vulnerabilities",
      "Perform Root Cause Analysis on Security Vulnerabilities",
      "Establish and Manage an Inventory of Third-Party Software Components",
      "Use Up-to-Date and Trusted Third-Party Software Components",
      "Establish and Maintain a Severity Rating System and Process for Application Vulnerabilities",
      "Use Standard Hardening Configuration Templates for Application Infrastructure",
      "Separate Production and Non-Production Systems",
      "Train Developers in Application Security Concepts and Secure Coding",
      "Apply Secure Design Principles in Application Architectures",
      "Leverage Vetted Modules or Services for Application Security Components",
      "Implement Code-Level Security Checks",
      "Conduct Application Penetration Testing",
      "Conduct Threat Modeling"
    ]
  },
  {
    group: "17. Incident Response Management",
    safeguards: [
      "Designate Personnel to Manage Incident Handling",
      "Establish and Maintain Contact Information for Reporting Security Incidents",
      "Establish and Maintain an Enterprise Process for Reporting Incidents",
      "Establish and Maintain an Incident Response Process",
      "Assign Key Roles and Responsibilities",
      "Define Mechanisms for Communicating During Incident Response",
      "Conduct Routine Incident Response Exercises",
      "Conduct Post-Incident Reviews",
      "Establish and Maintain Security Incident Thresholds"
    ]
  },
  {
    group: "18. Penetration Testing",
    safeguards: [
      "Establish and Maintain a Penetration Testing Program",
      "Perform Periodic External Penetration Tests",
      "Remediate Penetration Test Findings",
      "Validate Penetration Testing",
      "Perform Periodic Internal Penetration Tests"
    ]
  }
];

let output = "  'CIS Controls v8': [\n";
controls.forEach((control, cIdx) => {
  const controlNum = cIdx + 1;
  control.safeguards.forEach((sg, sgIdx) => {
    const sgNum = sgIdx + 1;
    const id = `${controlNum}.${sgNum}`;
    output += `    { id: '${id}', group: '${control.group}', title: '${sg.replace(/'/g, "\\'")}', description: '${sg.replace(/'/g, "\\'")}' },\n`;
  });
});
output += "  ],";

fs.writeFileSync('cis_output.txt', output);
console.log('Done');
