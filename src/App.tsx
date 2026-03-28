// CISO Tools Suite - Security Controls and Risk Assessment
import React, { useState, useEffect, useMemo, useRef } from 'react';
import { 
  Shield, 
  ShieldCheck,
  GlobeLock,
  Zap,
  BarChart3,
  Database, 
  FileText, 
  Plus, 
  Search, 
  Upload, 
  CheckCircle2, 
  AlertCircle, 
  ChevronRight, 
  Trash2, 
  Edit2, 
  Download,
  Loader2,
  X,
  Check,
  LogOut,
  LogIn,
  Settings,
  Sun,
  Moon,
  LayoutDashboard,
  BookOpen,
  ClipboardList,
  Activity,
  FileCheck,
  Lock,
  Menu,
  Bug,
  Server,
  Users,
  HardDrive,
  Cloud,
  ArrowRightLeft,
  XCircle,
  Crosshair,
  EyeOff,
  Key,
  Laptop,
  Radar
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import * as XLSX from 'xlsx';
import Papa from 'papaparse';
import { useDropzone } from 'react-dropzone';
import * as mammoth from 'mammoth';
import * as pdfjs from 'pdfjs-dist';
import { QAItem, MatchResult, Questionnaire, Risk, PentestResult, Vulnerability } from './types';
import { 
  auth, 
  db, 
  googleProvider, 
  signInWithPopup,
  signInWithRedirect, 
  getRedirectResult,
  signOut, 
  onAuthStateChanged, 
  handleFirestoreError, 
  OperationType,
  User
} from './firebase';
import { 
  collection, 
  query, 
  where, 
  onSnapshot, 
  doc, 
  setDoc, 
  deleteDoc, 
  updateDoc,
  orderBy,
  writeBatch
} from 'firebase/firestore';

// Set up PDF.js worker
pdfjs.GlobalWorkerOptions.workerSrc = `//cdnjs.cloudflare.com/ajax/libs/pdf.js/${pdfjs.version}/pdf.worker.min.js`;
import { matchQuestion, processQuestionnaire } from './services/geminiService';

type ComplianceStatus = 'Not Started' | 'In Progress' | 'Implemented' | 'Not Applicable';

type ComplianceControl = {
  id: string;
  group: string;
  title: string;
  description: string;
};

const FRAMEWORKS: Record<string, ComplianceControl[]> = {
  'NIST CSF 2.0': [
    // GOVERN (31)
    { id: 'GV.OC-01', group: 'Govern', title: 'Organizational Context', description: 'The organizational mission is understood and informs cybersecurity risk management.' },
    { id: 'GV.OC-02', group: 'Govern', title: 'Organizational Context', description: 'Internal and external stakeholders are understood, and their needs and expectations regarding cybersecurity risk management are understood and considered.' },
    { id: 'GV.OC-03', group: 'Govern', title: 'Organizational Context', description: 'Legal, regulatory, and contractual requirements regarding cybersecurity are understood and managed.' },
    { id: 'GV.OC-04', group: 'Govern', title: 'Organizational Context', description: 'Critical objectives, capabilities, and services that stakeholders depend on or expect from the organization are understood and communicated.' },
    { id: 'GV.OC-05', group: 'Govern', title: 'Organizational Context', description: 'Outcomes, capabilities, and services that the organization depends on are understood and communicated.' },
    { id: 'GV.RM-01', group: 'Govern', title: 'Risk Management Strategy', description: 'Risk management objectives are established and agreed to by organizational stakeholders.' },
    { id: 'GV.RM-02', group: 'Govern', title: 'Risk Management Strategy', description: 'Risk appetite and risk tolerance statements are established, communicated, and maintained.' },
    { id: 'GV.RM-03', group: 'Govern', title: 'Risk Management Strategy', description: 'Cybersecurity risk management activities and outcomes are included in enterprise risk management processes.' },
    { id: 'GV.RM-04', group: 'Govern', title: 'Risk Management Strategy', description: 'Strategic direction that describes appropriate risk response options is established and communicated.' },
    { id: 'GV.RM-05', group: 'Govern', title: 'Risk Management Strategy', description: 'Lines of communication across the organization are established for cybersecurity risks.' },
    { id: 'GV.RM-06', group: 'Govern', title: 'Risk Management Strategy', description: 'A standardized method for calculating, documenting, categorizing, and prioritizing cybersecurity risks is established and communicated.' },
    { id: 'GV.RM-07', group: 'Govern', title: 'Risk Management Strategy', description: 'Strategic opportunities are characterized and are included in organizational cybersecurity risk discussions.' },
    { id: 'GV.RR-01', group: 'Govern', title: 'Roles, Responsibilities, and Authorities', description: 'Organizational leadership is responsible and accountable for cybersecurity risk and fosters a culture that is risk-aware, ethical, and continually improving.' },
    { id: 'GV.RR-02', group: 'Govern', title: 'Roles, Responsibilities, and Authorities', description: 'Roles, responsibilities, and authorities related to cybersecurity risk management are established, communicated, understood, and enforced.' },
    { id: 'GV.RR-03', group: 'Govern', title: 'Roles, Responsibilities, and Authorities', description: 'Adequate resources are allocated commensurate with the cybersecurity risk strategy, roles, responsibilities, and policies.' },
    { id: 'GV.RR-04', group: 'Govern', title: 'Roles, Responsibilities, and Authorities', description: 'Cybersecurity is included in human resources practices.' },
    { id: 'GV.PO-01', group: 'Govern', title: 'Policy', description: 'Policy for managing cybersecurity risks is established, communicated, and enforced.' },
    { id: 'GV.PO-02', group: 'Govern', title: 'Policy', description: 'Policy for managing cybersecurity risks is reviewed, updated, communicated, and enforced.' },
    { id: 'GV.OV-01', group: 'Govern', title: 'Oversight', description: 'Cybersecurity risk management strategy outcomes are reviewed to inform and adjust strategy and direction.' },
    { id: 'GV.OV-02', group: 'Govern', title: 'Oversight', description: 'The cybersecurity risk management strategy is reviewed and adjusted to ensure coverage of organizational requirements and risks.' },
    { id: 'GV.OV-03', group: 'Govern', title: 'Oversight', description: 'Organizational cybersecurity risk management performance is evaluated and reviewed for adjustments needed.' },
    { id: 'GV.SC-01', group: 'Govern', title: 'Cybersecurity Supply Chain Risk Management', description: 'A cybersecurity supply chain risk management program, strategy, objectives, policies, and processes are established and agreed to by organizational stakeholders.' },
    { id: 'GV.SC-02', group: 'Govern', title: 'Cybersecurity Supply Chain Risk Management', description: 'Cybersecurity roles and responsibilities for suppliers, customers, and partners are established, communicated, and coordinated.' },
    { id: 'GV.SC-03', group: 'Govern', title: 'Cybersecurity Supply Chain Risk Management', description: 'Cybersecurity supply chain risk management is integrated into cybersecurity and enterprise risk management.' },
    { id: 'GV.SC-04', group: 'Govern', title: 'Cybersecurity Supply Chain Risk Management', description: 'Suppliers are known and prioritized by criticality.' },
    { id: 'GV.SC-05', group: 'Govern', title: 'Cybersecurity Supply Chain Risk Management', description: 'Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.' },
    { id: 'GV.SC-06', group: 'Govern', title: 'Cybersecurity Supply Chain Risk Management', description: 'Planning and due diligence are performed to manage cybersecurity risks before entering into formal supplier or other third-party relationships.' },
    { id: 'GV.SC-07', group: 'Govern', title: 'Cybersecurity Supply Chain Risk Management', description: 'The risks posed by a supplier, their products and services, and other third parties are understood, recorded, prioritized, assessed, responded to, and monitored.' },
    { id: 'GV.SC-08', group: 'Govern', title: 'Cybersecurity Supply Chain Risk Management', description: 'Relevant suppliers and other third parties are included in incident planning, response, and recovery activities.' },
    { id: 'GV.SC-09', group: 'Govern', title: 'Cybersecurity Supply Chain Risk Management', description: 'Supply chain security practices are integrated into cybersecurity and enterprise risk management programs.' },
    { id: 'GV.SC-10', group: 'Govern', title: 'Cybersecurity Supply Chain Risk Management', description: 'Cybersecurity supply chain risk management plans include provisioning for activities that occur after the conclusion of a partnership or service agreement.' },

    // IDENTIFY (22)
    { id: 'ID.AM-01', group: 'Identify', title: 'Asset Management', description: 'Inventories of hardware managed by the organization are maintained.' },
    { id: 'ID.AM-02', group: 'Identify', title: 'Asset Management', description: 'Inventories of software, services, and systems managed by the organization are maintained.' },
    { id: 'ID.AM-03', group: 'Identify', title: 'Asset Management', description: 'Representations of the organization\'s authorized network communication and internal and external network data flows are maintained.' },
    { id: 'ID.AM-04', group: 'Identify', title: 'Asset Management', description: 'Inventories of services provided by suppliers are maintained.' },
    { id: 'ID.AM-05', group: 'Identify', title: 'Asset Management', description: 'Assets are prioritized based on classification, criticality, resources, and impact on the mission.' },
    { id: 'ID.AM-07', group: 'Identify', title: 'Asset Management', description: 'Inventories of data and corresponding metadata for designated data types are maintained.' },
    { id: 'ID.AM-08', group: 'Identify', title: 'Asset Management', description: 'Systems, hardware, software, services, and data are managed throughout their life cycles.' },
    { id: 'ID.RA-01', group: 'Identify', title: 'Risk Assessment', description: 'Vulnerabilities in assets are identified, validated, and recorded.' },
    { id: 'ID.RA-02', group: 'Identify', title: 'Risk Assessment', description: 'Cyber threat intelligence is received from information sharing forums and sources.' },
    { id: 'ID.RA-03', group: 'Identify', title: 'Risk Assessment', description: 'Internal and external threats to the organization are identified and recorded.' },
    { id: 'ID.RA-04', group: 'Identify', title: 'Risk Assessment', description: 'Potential impacts and likelihoods of threats exploiting vulnerabilities are identified and recorded.' },
    { id: 'ID.RA-05', group: 'Identify', title: 'Risk Assessment', description: 'Threats, vulnerabilities, likelihoods, and impacts are used to determine risk and inform risk responses.' },
    { id: 'ID.RA-06', group: 'Identify', title: 'Risk Assessment', description: 'Risk responses are chosen, prioritized, planned, tracked, and communicated.' },
    { id: 'ID.RA-07', group: 'Identify', title: 'Risk Assessment', description: 'Changes in the organization and the threat environment are monitored and risk assessments are updated as needed.' },
    { id: 'ID.IM-01', group: 'Identify', title: 'Improvement', description: 'Improvements are identified from evaluations of cybersecurity performance and capabilities.' },
    { id: 'ID.IM-02', group: 'Identify', title: 'Improvement', description: 'Improvements are identified from security tests and exercises.' },
    { id: 'ID.IM-03', group: 'Identify', title: 'Improvement', description: 'Improvements are identified from execution of incident response and recovery plans.' },
    { id: 'ID.IM-04', group: 'Identify', title: 'Improvement', description: 'Incident response plans and other cybersecurity plans that affect suppliers and other third parties are updated to incorporate lessons learned.' },

    // PROTECT (24)
    { id: 'PR.AA-01', group: 'Protect', title: 'Identity Management, Authentication, and Access Control', description: 'Identities and credentials for authorized users, services, and hardware are managed by the organization.' },
    { id: 'PR.AA-02', group: 'Protect', title: 'Identity Management, Authentication, and Access Control', description: 'Identities are proofed and bound to credentials based on the context of interactions.' },
    { id: 'PR.AA-03', group: 'Protect', title: 'Identity Management, Authentication, and Access Control', description: 'Users, services, and hardware are authenticated.' },
    { id: 'PR.AA-04', group: 'Protect', title: 'Identity Management, Authentication, and Access Control', description: 'Identity assertions and credentials are appropriately protected.' },
    { id: 'PR.AA-05', group: 'Protect', title: 'Identity Management, Authentication, and Access Control', description: 'Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.' },
    { id: 'PR.AA-06', group: 'Protect', title: 'Identity Management, Authentication, and Access Control', description: 'Physical access to assets is managed, monitored, and enforced commensurate with risk.' },
    { id: 'PR.AT-01', group: 'Protect', title: 'Awareness and Training', description: 'Personnel are provided with actionable, tailored cybersecurity awareness and training.' },
    { id: 'PR.AT-02', group: 'Protect', title: 'Awareness and Training', description: 'Individuals with specialized cybersecurity responsibilities are provided with tailored cybersecurity training.' },
    { id: 'PR.DS-01', group: 'Protect', title: 'Data Security', description: 'The confidentiality, integrity, and availability of data-at-rest are protected.' },
    { id: 'PR.DS-02', group: 'Protect', title: 'Data Security', description: 'The confidentiality, integrity, and availability of data-in-transit are protected.' },
    { id: 'PR.DS-10', group: 'Protect', title: 'Data Security', description: 'The confidentiality, integrity, and availability of data-in-use are protected.' },
    { id: 'PR.DS-11', group: 'Protect', title: 'Data Security', description: 'Backups of data are created, protected, maintained, and tested.' },
    { id: 'PR.PS-01', group: 'Protect', title: 'Platform Security', description: 'Configuration management plans are established and maintained.' },
    { id: 'PR.PS-02', group: 'Protect', title: 'Platform Security', description: 'Software is maintained, replaced, and removed commensurate with risk.' },
    { id: 'PR.PS-03', group: 'Protect', title: 'Platform Security', description: 'Hardware is maintained, replaced, and removed commensurate with risk.' },
    { id: 'PR.PS-04', group: 'Protect', title: 'Platform Security', description: 'Log records are generated and made available for continuous monitoring.' },
    { id: 'PR.PS-05', group: 'Protect', title: 'Platform Security', description: 'Installation and execution of unauthorized software are prevented.' },
    { id: 'PR.PS-06', group: 'Protect', title: 'Platform Security', description: 'Secure software development practices are integrated, and their performance is monitored throughout the software development life cycle.' },
    { id: 'PR.IR-01', group: 'Protect', title: 'Technology Infrastructure Resilience', description: 'Networks and environments are protected from unauthorized logical access and usage.' },
    { id: 'PR.IR-02', group: 'Protect', title: 'Technology Infrastructure Resilience', description: 'The organization’s technology assets are protected from environmental threats.' },
    { id: 'PR.IR-03', group: 'Protect', title: 'Technology Infrastructure Resilience', description: 'Mechanisms are implemented to achieve resilience requirements in normal and adverse situations.' },
    { id: 'PR.IR-04', group: 'Protect', title: 'Technology Infrastructure Resilience', description: 'Adequate resource capacity to ensure availability is maintained.' },

    // DETECT (11)
    { id: 'DE.CM-01', group: 'Detect', title: 'Continuous Monitoring', description: 'Networks and network services are monitored to find potentially adverse events.' },
    { id: 'DE.CM-02', group: 'Detect', title: 'Continuous Monitoring', description: 'The physical environment is monitored to find potentially adverse events.' },
    { id: 'DE.CM-03', group: 'Detect', title: 'Continuous Monitoring', description: 'Personnel activity and technology usage are monitored to find potentially adverse events.' },
    { id: 'DE.CM-06', group: 'Detect', title: 'Continuous Monitoring', description: 'External service provider activities and services are monitored to find potentially adverse events.' },
    { id: 'DE.CM-09', group: 'Detect', title: 'Continuous Monitoring', description: 'Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events.' },
    { id: 'DE.AE-02', group: 'Detect', title: 'Adverse Event Analysis', description: 'Potentially adverse events are analyzed to better understand associated activities.' },
    { id: 'DE.AE-03', group: 'Detect', title: 'Adverse Event Analysis', description: 'Information is correlated from multiple sources.' },
    { id: 'DE.AE-04', group: 'Detect', title: 'Adverse Event Analysis', description: 'The estimated impact of events is determined.' },
    { id: 'DE.AE-06', group: 'Detect', title: 'Adverse Event Analysis', description: 'Incident alerts are generated.' },
    { id: 'DE.AE-07', group: 'Detect', title: 'Adverse Event Analysis', description: 'Cyber threat intelligence and other contextual information are integrated into the analysis.' },
    { id: 'DE.AE-08', group: 'Detect', title: 'Adverse Event Analysis', description: 'Incidents are declared.' },

    // RESPOND (13)
    { id: 'RS.MA-01', group: 'Respond', title: 'Incident Management', description: 'The incident response plan is executed in coordination with relevant third parties once an incident is declared.' },
    { id: 'RS.MA-02', group: 'Respond', title: 'Incident Management', description: 'Incident reports are triaged and validated.' },
    { id: 'RS.MA-03', group: 'Respond', title: 'Incident Management', description: 'Incidents are categorized and prioritized.' },
    { id: 'RS.MA-04', group: 'Respond', title: 'Incident Management', description: 'Incidents are escalated or elevated as needed.' },
    { id: 'RS.MA-05', group: 'Respond', title: 'Incident Management', description: 'The criteria for initiating incident recovery are applied.' },
    { id: 'RS.AN-03', group: 'Respond', title: 'Incident Analysis', description: 'Analysis is performed to establish what has taken place during an incident and the root cause of the incident.' },
    { id: 'RS.AN-06', group: 'Respond', title: 'Incident Analysis', description: 'Actions performed during an investigation are recorded, and the records\' integrity and provenance are preserved.' },
    { id: 'RS.AN-07', group: 'Respond', title: 'Incident Analysis', description: 'Incident data and metadata are collected, and their integrity and provenance are preserved.' },
    { id: 'RS.AN-08', group: 'Respond', title: 'Incident Analysis', description: 'An incident\'s magnitude is estimated and validated.' },
    { id: 'RS.CO-02', group: 'Respond', title: 'Incident Response Reporting and Communication', description: 'Internal and external stakeholders are notified of incidents.' },
    { id: 'RS.CO-03', group: 'Respond', title: 'Incident Response Reporting and Communication', description: 'Information is shared with designated internal and external stakeholders.' },
    { id: 'RS.MI-01', group: 'Respond', title: 'Incident Mitigation', description: 'Incidents are contained.' },
    { id: 'RS.MI-02', group: 'Respond', title: 'Incident Mitigation', description: 'Incidents are eradicated.' },

    // RECOVER (8)
    { id: 'RC.RP-01', group: 'Recover', title: 'Incident Recovery Plan Execution', description: 'The incident recovery plan is executed once incident recovery is initiated.' },
    { id: 'RC.RP-02', group: 'Recover', title: 'Incident Recovery Plan Execution', description: 'Recovery activities are selected, prioritized, and performed.' },
    { id: 'RC.RP-03', group: 'Recover', title: 'Incident Recovery Plan Execution', description: 'The integrity of backups and other restoration assets is verified before using them for restoration.' },
    { id: 'RC.RP-04', group: 'Recover', title: 'Incident Recovery Plan Execution', description: 'Critical assets are restored.' },
    { id: 'RC.RP-05', group: 'Recover', title: 'Incident Recovery Plan Execution', description: 'Restored assets are verified as meeting the organization\'s requirements.' },
    { id: 'RC.RP-06', group: 'Recover', title: 'Incident Recovery Plan Execution', description: 'The incident recovery plan is updated to reflect changes made during recovery.' },
    { id: 'RC.CO-03', group: 'Recover', title: 'Incident Recovery Communication', description: 'Recovery activities and progress are communicated to internal and external stakeholders.' },
    { id: 'RC.CO-04', group: 'Recover', title: 'Incident Recovery Communication', description: 'Public relations and reputation are managed.' }
  ],
  'ISO 27001:2022': [
    { id: '5.1', group: 'Organizational', title: 'Policies for information security', description: 'Information security policy and topic-specific policies shall be defined, approved by management, published, communicated to and acknowledged by relevant personnel and relevant interested parties, and reviewed at planned intervals and if significant changes occur.' },
    { id: '5.2', group: 'Organizational', title: 'Information security roles and responsibilities', description: 'Information security roles and responsibilities shall be defined and allocated according to the organization needs.' },
    { id: '5.3', group: 'Organizational', title: 'Segregation of duties', description: 'Conflicting duties and conflicting areas of responsibility shall be segregated to reduce opportunities for unauthorized or unintentional modification or misuse of the organization\'s assets.' },
    { id: '5.4', group: 'Organizational', title: 'Management responsibilities', description: 'Management shall require all personnel to apply information security in accordance with the established information security policy and topic-specific policies and procedures of the organization.' },
    { id: '5.5', group: 'Organizational', title: 'Contact with authorities', description: 'The organization shall establish and maintain contact with relevant authorities.' },
    { id: '5.6', group: 'Organizational', title: 'Contact with special interest groups', description: 'The organization shall establish and maintain contact with special interest groups or other specialist security forums and professional associations.' },
    { id: '5.7', group: 'Organizational', title: 'Threat intelligence', description: 'Information relating to information security threats shall be collected and analysed to produce threat intelligence.' },
    { id: '5.8', group: 'Organizational', title: 'Information security in project management', description: 'Information security shall be integrated into project management.' },
    { id: '5.9', group: 'Organizational', title: 'Inventory of information and other associated assets', description: 'An inventory of information and other associated assets, including owners, shall be developed and maintained.' },
    { id: '5.10', group: 'Organizational', title: 'Acceptable use of information and other associated assets', description: 'Rules for the acceptable use and procedures for handling information and other associated assets shall be identified, documented and implemented.' },
    { id: '5.11', group: 'Organizational', title: 'Return of assets', description: 'Personnel and other interested parties as appropriate shall return all the organization\'s assets in their possession upon change or termination of their employment, contract or agreement.' },
    { id: '5.12', group: 'Organizational', title: 'Classification of information', description: 'Information shall be classified according to the information security needs of the organization based on confidentiality, integrity, availability and relevant interested party requirements.' },
    { id: '5.13', group: 'Organizational', title: 'Labelling of information', description: 'An appropriate set of procedures for information labelling shall be developed and implemented in accordance with the information classification scheme adopted by the organization.' },
    { id: '5.14', group: 'Organizational', title: 'Information transfer', description: 'Information transfer rules, procedures, or agreements shall be in place for all types of transfer facilities within the organization and between the organization and other parties.' },
    { id: '5.15', group: 'Organizational', title: 'Access control', description: 'Rules to control physical and logical access to information and other associated assets shall be established and implemented based on business and information security requirements.' },
    { id: '5.16', group: 'Organizational', title: 'Identity management', description: 'The full life cycle of identities shall be managed.' },
    { id: '5.17', group: 'Organizational', title: 'Authentication information', description: 'Allocation and management of authentication information shall be controlled by a management process, including advising personnel on the appropriate handling of authentication information.' },
    { id: '5.18', group: 'Organizational', title: 'Access rights', description: 'Access rights to information and other associated assets shall be provisioned, reviewed, modified and removed in accordance with the organization’s topic-specific policy on and rules for access control.' },
    { id: '5.19', group: 'Organizational', title: 'Information security in supplier relationships', description: 'Processes and procedures shall be defined and implemented to manage the information security risks associated with the use of supplier’s products or services.' },
    { id: '5.20', group: 'Organizational', title: 'Addressing information security within supplier agreements', description: 'Relevant information security requirements shall be established and agreed with each supplier based on the type of supplier relationship.' },
    { id: '5.21', group: 'Organizational', title: 'Managing information security in the ICT supply chain', description: 'Processes and procedures shall be defined and implemented to manage the information security risks associated with the ICT products and services supply chain.' },
    { id: '5.22', group: 'Organizational', title: 'Monitoring, review and change management of supplier services', description: 'The organization shall regularly monitor, review, evaluate and manage change in supplier information security practices and service delivery.' },
    { id: '5.23', group: 'Organizational', title: 'Information security for use of cloud services', description: 'Processes for acquisition, use, management and exit from cloud services shall be established in accordance with the organization’s information security requirements.' },
    { id: '5.24', group: 'Organizational', title: 'Information security incident management planning and preparation', description: 'The organization shall plan and prepare for managing information security incidents by defining, establishing and communicating information security incident management processes, roles and responsibilities.' },
    { id: '5.25', group: 'Organizational', title: 'Assessment and decision on information security events', description: 'The organization shall assess information security events and decide if they are to be categorized as information security incidents.' },
    { id: '5.26', group: 'Organizational', title: 'Response to information security incidents', description: 'Information security incidents shall be responded to in accordance with the documented procedures.' },
    { id: '5.27', group: 'Organizational', title: 'Learning from information security incidents', description: 'Knowledge gained from information security incidents shall be used to strengthen and improve the information security controls.' },
    { id: '5.28', group: 'Organizational', title: 'Collection of evidence', description: 'The organization shall establish and implement procedures for the identification, collection, acquisition and preservation of evidence related to information security events.' },
    { id: '5.29', group: 'Organizational', title: 'Information security during disruption', description: 'The organization shall plan how to maintain information security at an appropriate level during disruption.' },
    { id: '5.30', group: 'Organizational', title: 'ICT readiness for business continuity', description: 'ICT readiness shall be planned, implemented, maintained and tested based on business continuity objectives and ICT continuity requirements.' },
    { id: '5.31', group: 'Organizational', title: 'Legal, statutory, regulatory and contractual requirements', description: 'Legal, statutory, regulatory and contractual requirements relevant to information security and the organization’s approach to meet these requirements shall be identified, documented and kept up to date.' },
    { id: '5.32', group: 'Organizational', title: 'Intellectual property rights', description: 'The organization shall implement appropriate procedures to protect intellectual property rights.' },
    { id: '5.33', group: 'Organizational', title: 'Protection of records', description: 'Records shall be protected from loss, destruction, falsification, unauthorized access and unauthorized release.' },
    { id: '5.34', group: 'Organizational', title: 'Privacy and protection of PII', description: 'The organization shall identify and meet the requirements regarding the preservation of privacy and protection of PII according to applicable laws and regulations and contractual requirements.' },
    { id: '5.35', group: 'Organizational', title: 'Independent review of information security', description: 'The organization’s approach to managing information security and its implementation including people, processes and technologies shall be reviewed independently at planned intervals, or when significant changes occur.' },
    { id: '5.36', group: 'Organizational', title: 'Compliance with policies, rules and standards for information security', description: 'Compliance with the organization’s information security policy, topic-specific policies, rules and standards shall be regularly reviewed.' },
    { id: '5.37', group: 'Organizational', title: 'Documented operating procedures', description: 'Operating procedures for information processing facilities shall be documented and made available to personnel who need them.' },
    { id: '6.1', group: 'People', title: 'Screening', description: 'Background verification checks on all candidates to become personnel shall be carried out prior to joining the organization and on an ongoing basis taking into consideration applicable laws, regulations and ethics and proportional to the business requirements, the classification of the information to be accessed and the perceived risks.' },
    { id: '6.2', group: 'People', title: 'Terms and conditions of employment', description: 'The employment contractual agreements shall state the personnel’s and the organization’s responsibilities for information security.' },
    { id: '6.3', group: 'People', title: 'Information security awareness, education and training', description: 'Personnel of the organization and relevant interested parties shall receive appropriate information security awareness, education and training and regular updates of the organization\'s information security policy, topic-specific policies and procedures, as relevant for their job function.' },
    { id: '6.4', group: 'People', title: 'Disciplinary process', description: 'A disciplinary process shall be formalized and communicated to take actions against personnel and other relevant interested parties who have committed an information security policy violation.' },
    { id: '6.5', group: 'People', title: 'Responsibilities after termination or change of employment', description: 'Information security responsibilities and duties that remain valid after termination or change of employment shall be defined, enforced and communicated to relevant personnel and other interested parties.' },
    { id: '6.6', group: 'People', title: 'Confidentiality or non-disclosure agreements', description: 'Confidentiality or non-disclosure agreements reflecting the organization’s needs for the protection of information shall be identified, documented, regularly reviewed and signed by personnel and other relevant interested parties.' },
    { id: '6.7', group: 'People', title: 'Remote working', description: 'Security measures shall be implemented when personnel are working remotely to protect information accessed, processed or stored outside the organization’s premises.' },
    { id: '6.8', group: 'People', title: 'Information security event reporting', description: 'The organization shall provide a mechanism for personnel to report observed or suspected information security events through appropriate channels in a timely manner.' },
    { id: '7.1', group: 'Physical', title: 'Physical security perimeters', description: 'Security perimeters shall be defined and used to protect areas that contain information and other associated assets.' },
    { id: '7.2', group: 'Physical', title: 'Physical entry', description: 'Secure areas shall be protected by appropriate entry controls and access points.' },
    { id: '7.3', group: 'Physical', title: 'Securing offices, rooms and facilities', description: 'Physical security for offices, rooms and facilities shall be designed and implemented.' },
    { id: '7.4', group: 'Physical', title: 'Physical security monitoring', description: 'Premises shall be continuously monitored for unauthorized physical access.' },
    { id: '7.5', group: 'Physical', title: 'Protecting against external and environmental threats', description: 'Protection against physical and environmental threats, such as natural disasters and other intentional or unintentional physical threats to infrastructure shall be designed and implemented.' },
    { id: '7.6', group: 'Physical', title: 'Working in secure areas', description: 'Security measures for working in secure areas shall be designed and implemented.' },
    { id: '7.7', group: 'Physical', title: 'Clear desk and clear screen', description: 'Clear desk rules for papers and removable storage media and clear screen rules for information processing facilities shall be defined and appropriately enforced.' },
    { id: '7.8', group: 'Physical', title: 'Equipment siting and protection', description: 'Equipment shall be sited securely and protected.' },
    { id: '7.9', group: 'Physical', title: 'Security of assets off-premises', description: 'Off-site assets shall be protected.' },
    { id: '7.10', group: 'Physical', title: 'Storage media', description: 'Storage media shall be managed through their life cycle of acquisition, use, transportation and disposal in accordance with the organization’s classification scheme and handling requirements.' },
    { id: '7.11', group: 'Physical', title: 'Supporting utilities', description: 'Information processing facilities shall be protected from power failures and other disruptions caused by failures in supporting utilities.' },
    { id: '7.12', group: 'Physical', title: 'Cabling security', description: 'Cables carrying power, data or supporting information services shall be protected from interception, interference or damage.' },
    { id: '7.13', group: 'Physical', title: 'Equipment maintenance', description: 'Equipment shall be maintained correctly to ensure availability, integrity and confidentiality of information.' },
    { id: '7.14', group: 'Physical', title: 'Secure disposal or re-use of equipment', description: 'Items of equipment containing storage media shall be verified to ensure that any sensitive data and licensed software has been removed or securely overwritten prior to disposal or re-use.' },
    { id: '8.1', group: 'Technological', title: 'User endpoint devices', description: 'Information stored on, processed by or routed via user endpoint devices shall be protected.' },
    { id: '8.2', group: 'Technological', title: 'Privileged access rights', description: 'The allocation and use of privileged access rights shall be restricted and managed.' },
    { id: '8.3', group: 'Technological', title: 'Information access restriction', description: 'Access to information and other associated assets shall be restricted in accordance with the established topic-specific policy on access control.' },
    { id: '8.4', group: 'Technological', title: 'Access to source code', description: 'Read and write access to source code, development tools and software libraries shall be appropriately managed.' },
    { id: '8.5', group: 'Technological', title: 'Secure authentication', description: 'Secure authentication technologies and procedures shall be implemented based on information access restrictions and the topic-specific policy on access control.' },
    { id: '8.6', group: 'Technological', title: 'Capacity management', description: 'The use of resources shall be monitored and adjusted in line with current and expected capacity requirements.' },
    { id: '8.7', group: 'Technological', title: 'Protection against malware', description: 'Protection against malware shall be implemented and supported by appropriate user awareness.' },
    { id: '8.8', group: 'Technological', title: 'Management of technical vulnerabilities', description: 'Information about technical vulnerabilities of information systems in use shall be obtained, the organization\'s exposure to such vulnerabilities shall be evaluated and appropriate measures shall be taken.' },
    { id: '8.9', group: 'Technological', title: 'Configuration management', description: 'Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed.' },
    { id: '8.10', group: 'Technological', title: 'Information deletion', description: 'Information stored in information systems, devices or in any other storage media shall be deleted when no longer required.' },
    { id: '8.11', group: 'Technological', title: 'Data masking', description: 'Data masking shall be used in accordance with the organization’s topic-specific policy on access control and other related topic-specific policies, and business requirements, taking into consideration applicable legislation.' },
    { id: '8.12', group: 'Technological', title: 'Data leakage prevention', description: 'Data leakage prevention measures shall be applied to systems, networks and any other devices that process, store or transmit sensitive information.' },
    { id: '8.13', group: 'Technological', title: 'Information backup', description: 'Backup copies of information, software and systems shall be maintained and regularly tested in accordance with the agreed topic-specific policy on backup.' },
    { id: '8.14', group: 'Technological', title: 'Redundancy of information processing facilities', description: 'Information processing facilities shall be implemented with sufficient redundancy to meet availability requirements.' },
    { id: '8.15', group: 'Technological', title: 'Logging', description: 'Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed.' },
    { id: '8.16', group: 'Technological', title: 'Monitoring activities', description: 'Networks, systems and applications shall be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents.' },
    { id: '8.17', group: 'Technological', title: 'Clock synchronization', description: 'The clocks of information processing systems used by the organization shall be synchronized to approved time sources.' },
    { id: '8.18', group: 'Technological', title: 'Use of privileged utility programs', description: 'The use of utility programs that can be capable of overriding system and application controls shall be restricted and tightly controlled.' },
    { id: '8.19', group: 'Technological', title: 'Installation of software on operational systems', description: 'Procedures and measures shall be implemented to securely manage software installation on operational systems.' },
    { id: '8.20', group: 'Technological', title: 'Networks security', description: 'Networks and network devices shall be secured, managed and controlled to protect information in systems and applications.' },
    { id: '8.21', group: 'Technological', title: 'Security of network services', description: 'Security mechanisms, service levels and management requirements of network services shall be identified, implemented and monitored.' },
    { id: '8.22', group: 'Technological', title: 'Segregation of networks', description: 'Groups of information services, users and information systems shall be segregated in the organization’s networks.' },
    { id: '8.23', group: 'Technological', title: 'Web filtering', description: 'Access to external websites shall be managed to reduce exposure to malicious content.' },
    { id: '8.24', group: 'Technological', title: 'Use of cryptography', description: 'Rules for the effective and acceptable use of cryptographic controls, including cryptographic key management, shall be defined and implemented.' },
    { id: '8.25', group: 'Technological', title: 'Secure development life cycle', description: 'Rules for the secure development of software and systems shall be established and applied.' },
    { id: '8.26', group: 'Technological', title: 'Application security requirements', description: 'Information security requirements shall be identified, specified and approved when developing or acquiring applications.' },
    { id: '8.27', group: 'Technological', title: 'Secure system architecture and engineering principles', description: 'Principles for engineering secure systems shall be established, documented, maintained and applied to any information system development activities.' },
    { id: '8.28', group: 'Technological', title: 'Secure coding', description: 'Secure coding principles shall be applied to software development.' },
    { id: '8.29', group: 'Technological', title: 'Security testing in development and acceptance', description: 'Security testing processes shall be defined and implemented in the development life cycle.' },
    { id: '8.30', group: 'Technological', title: 'Outsourced development', description: 'The organization shall direct, monitor and review the activities related to outsourced system development.' },
    { id: '8.31', group: 'Technological', title: 'Separation of development, test and production environments', description: 'Development, testing and production environments shall be separated and secured.' },
    { id: '8.32', group: 'Technological', title: 'Change management', description: 'Changes to information processing facilities and information systems shall be subject to change management procedures.' },
    { id: '8.33', group: 'Technological', title: 'Test information', description: 'Test information shall be carefully selected, protected and managed.' },
    { id: '8.34', group: 'Technological', title: 'Protection of information systems during audit testing', description: 'Audit tests and other assurance activities involving assessment of operational systems shall be planned and agreed between the tester and appropriate management.' }
  ],
  'CIS Controls v8': [
    { id: '1.1', group: '1. Inventory and Control of Enterprise Assets', title: 'Establish and Maintain Detailed Enterprise Asset Inventory', description: 'Establish and Maintain Detailed Enterprise Asset Inventory' },
    { id: '1.2', group: '1. Inventory and Control of Enterprise Assets', title: 'Address Unauthorized Assets', description: 'Address Unauthorized Assets' },
    { id: '1.3', group: '1. Inventory and Control of Enterprise Assets', title: 'Utilize an Active Discovery Tool', description: 'Utilize an Active Discovery Tool' },
    { id: '1.4', group: '1. Inventory and Control of Enterprise Assets', title: 'Use Dynamic Host Configuration Protocol (DHCP) Logging to Update Enterprise Asset Inventory', description: 'Use Dynamic Host Configuration Protocol (DHCP) Logging to Update Enterprise Asset Inventory' },
    { id: '1.5', group: '1. Inventory and Control of Enterprise Assets', title: 'Use a Passive Asset Discovery Tool', description: 'Use a Passive Asset Discovery Tool' },
    { id: '2.1', group: '2. Inventory and Control of Software Assets', title: 'Establish and Maintain a Software Inventory', description: 'Establish and Maintain a Software Inventory' },
    { id: '2.2', group: '2. Inventory and Control of Software Assets', title: 'Ensure Authorized Software is Currently Supported', description: 'Ensure Authorized Software is Currently Supported' },
    { id: '2.3', group: '2. Inventory and Control of Software Assets', title: 'Address Unauthorized Software', description: 'Address Unauthorized Software' },
    { id: '2.4', group: '2. Inventory and Control of Software Assets', title: 'Utilize Automated Software Inventory Tools', description: 'Utilize Automated Software Inventory Tools' },
    { id: '2.5', group: '2. Inventory and Control of Software Assets', title: 'Allowlist Authorized Software', description: 'Allowlist Authorized Software' },
    { id: '2.6', group: '2. Inventory and Control of Software Assets', title: 'Allowlist Authorized Libraries', description: 'Allowlist Authorized Libraries' },
    { id: '2.7', group: '2. Inventory and Control of Software Assets', title: 'Allowlist Authorized Scripts', description: 'Allowlist Authorized Scripts' },
    { id: '3.1', group: '3. Data Protection', title: 'Establish and Maintain a Data Management Process', description: 'Establish and Maintain a Data Management Process' },
    { id: '3.2', group: '3. Data Protection', title: 'Establish and Maintain a Data Inventory', description: 'Establish and Maintain a Data Inventory' },
    { id: '3.3', group: '3. Data Protection', title: 'Configure Data Access Control Lists', description: 'Configure Data Access Control Lists' },
    { id: '3.4', group: '3. Data Protection', title: 'Enforce Data Retention', description: 'Enforce Data Retention' },
    { id: '3.5', group: '3. Data Protection', title: 'Securely Dispose of Data', description: 'Securely Dispose of Data' },
    { id: '3.6', group: '3. Data Protection', title: 'Encrypt Data on End-User Devices', description: 'Encrypt Data on End-User Devices' },
    { id: '3.7', group: '3. Data Protection', title: 'Establish and Maintain a Data Classification Scheme', description: 'Establish and Maintain a Data Classification Scheme' },
    { id: '3.8', group: '3. Data Protection', title: 'Document Data Flows', description: 'Document Data Flows' },
    { id: '3.9', group: '3. Data Protection', title: 'Encrypt Data on Removable Media', description: 'Encrypt Data on Removable Media' },
    { id: '3.10', group: '3. Data Protection', title: 'Encrypt Sensitive Data in Transit', description: 'Encrypt Sensitive Data in Transit' },
    { id: '3.11', group: '3. Data Protection', title: 'Encrypt Sensitive Data at Rest', description: 'Encrypt Sensitive Data at Rest' },
    { id: '3.12', group: '3. Data Protection', title: 'Segment Data Processing and Storage Based on Sensitivity', description: 'Segment Data Processing and Storage Based on Sensitivity' },
    { id: '3.13', group: '3. Data Protection', title: 'Deploy a Data Loss Prevention Solution', description: 'Deploy a Data Loss Prevention Solution' },
    { id: '3.14', group: '3. Data Protection', title: 'Log Sensitive Data Access', description: 'Log Sensitive Data Access' },
    { id: '4.1', group: '4. Secure Configuration of Enterprise Assets and Software', title: 'Establish and Maintain a Secure Configuration Process', description: 'Establish and Maintain a Secure Configuration Process' },
    { id: '4.2', group: '4. Secure Configuration of Enterprise Assets and Software', title: 'Establish and Maintain a Secure Configuration Process for Network Infrastructure', description: 'Establish and Maintain a Secure Configuration Process for Network Infrastructure' },
    { id: '4.3', group: '4. Secure Configuration of Enterprise Assets and Software', title: 'Configure Automatic Session Locking on Enterprise Assets', description: 'Configure Automatic Session Locking on Enterprise Assets' },
    { id: '4.4', group: '4. Secure Configuration of Enterprise Assets and Software', title: 'Implement and Manage a Firewall on Servers', description: 'Implement and Manage a Firewall on Servers' },
    { id: '4.5', group: '4. Secure Configuration of Enterprise Assets and Software', title: 'Implement and Manage a Firewall on End-User Devices', description: 'Implement and Manage a Firewall on End-User Devices' },
    { id: '4.6', group: '4. Secure Configuration of Enterprise Assets and Software', title: 'Securely Manage Enterprise Assets and Software', description: 'Securely Manage Enterprise Assets and Software' },
    { id: '4.7', group: '4. Secure Configuration of Enterprise Assets and Software', title: 'Manage Default Accounts on Enterprise Assets and Software', description: 'Manage Default Accounts on Enterprise Assets and Software' },
    { id: '4.8', group: '4. Secure Configuration of Enterprise Assets and Software', title: 'Uninstall or Disable Unnecessary Services on Enterprise Assets and Software', description: 'Uninstall or Disable Unnecessary Services on Enterprise Assets and Software' },
    { id: '4.9', group: '4. Secure Configuration of Enterprise Assets and Software', title: 'Configure Trusted DNS Servers on Enterprise Assets', description: 'Configure Trusted DNS Servers on Enterprise Assets' },
    { id: '4.10', group: '4. Secure Configuration of Enterprise Assets and Software', title: 'Enforce Automatic Device Lockout on Portable End-User Devices', description: 'Enforce Automatic Device Lockout on Portable End-User Devices' },
    { id: '4.11', group: '4. Secure Configuration of Enterprise Assets and Software', title: 'Enforce Remote Wipe Capability on Portable End-User Devices', description: 'Enforce Remote Wipe Capability on Portable End-User Devices' },
    { id: '4.12', group: '4. Secure Configuration of Enterprise Assets and Software', title: 'Separate Enterprise Workspaces on Mobile End-User Devices', description: 'Separate Enterprise Workspaces on Mobile End-User Devices' },
    { id: '5.1', group: '5. Account Management', title: 'Establish and Maintain an Inventory of Accounts', description: 'Establish and Maintain an Inventory of Accounts' },
    { id: '5.2', group: '5. Account Management', title: 'Use Unique Passwords', description: 'Use Unique Passwords' },
    { id: '5.3', group: '5. Account Management', title: 'Disable Dormant Accounts', description: 'Disable Dormant Accounts' },
    { id: '5.4', group: '5. Account Management', title: 'Restrict Administrator Privileges to Dedicated Administrator Accounts', description: 'Restrict Administrator Privileges to Dedicated Administrator Accounts' },
    { id: '5.5', group: '5. Account Management', title: 'Establish and Maintain an Inventory of Service Accounts', description: 'Establish and Maintain an Inventory of Service Accounts' },
    { id: '5.6', group: '5. Account Management', title: 'Centralize Account Management', description: 'Centralize Account Management' },
    { id: '6.1', group: '6. Access Control Management', title: 'Establish an Access Granting Process', description: 'Establish an Access Granting Process' },
    { id: '6.2', group: '6. Access Control Management', title: 'Establish an Access Revoking Process', description: 'Establish an Access Revoking Process' },
    { id: '6.3', group: '6. Access Control Management', title: 'Require MFA for Externally-Exposed Applications', description: 'Require MFA for Externally-Exposed Applications' },
    { id: '6.4', group: '6. Access Control Management', title: 'Require MFA for Remote Network Access', description: 'Require MFA for Remote Network Access' },
    { id: '6.5', group: '6. Access Control Management', title: 'Require MFA for Administrative Access', description: 'Require MFA for Administrative Access' },
    { id: '6.6', group: '6. Access Control Management', title: 'Establish and Maintain an Inventory of Authentication and Authorization Systems', description: 'Establish and Maintain an Inventory of Authentication and Authorization Systems' },
    { id: '6.7', group: '6. Access Control Management', title: 'Centralize Access Control', description: 'Centralize Access Control' },
    { id: '6.8', group: '6. Access Control Management', title: 'Define and Maintain Role-Based Access Control', description: 'Define and Maintain Role-Based Access Control' },
    { id: '7.1', group: '7. Continuous Vulnerability Management', title: 'Establish and Maintain a Vulnerability Management Process', description: 'Establish and Maintain a Vulnerability Management Process' },
    { id: '7.2', group: '7. Continuous Vulnerability Management', title: 'Establish and Maintain a Remediation Process', description: 'Establish and Maintain a Remediation Process' },
    { id: '7.3', group: '7. Continuous Vulnerability Management', title: 'Perform Automated Operating System Patch Management', description: 'Perform Automated Operating System Patch Management' },
    { id: '7.4', group: '7. Continuous Vulnerability Management', title: 'Perform Automated Application Patch Management', description: 'Perform Automated Application Patch Management' },
    { id: '7.5', group: '7. Continuous Vulnerability Management', title: 'Perform Automated Vulnerability Scans of Internal Enterprise Assets', description: 'Perform Automated Vulnerability Scans of Internal Enterprise Assets' },
    { id: '7.6', group: '7. Continuous Vulnerability Management', title: 'Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets', description: 'Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets' },
    { id: '7.7', group: '7. Continuous Vulnerability Management', title: 'Remediate Detected Vulnerabilities', description: 'Remediate Detected Vulnerabilities' },
    { id: '8.1', group: '8. Audit Log Management', title: 'Establish and Maintain an Audit Log Management Process', description: 'Establish and Maintain an Audit Log Management Process' },
    { id: '8.2', group: '8. Audit Log Management', title: 'Collect Audit Logs', description: 'Collect Audit Logs' },
    { id: '8.3', group: '8. Audit Log Management', title: 'Ensure Adequate Audit Log Storage', description: 'Ensure Adequate Audit Log Storage' },
    { id: '8.4', group: '8. Audit Log Management', title: 'Standardize Time Synchronization', description: 'Standardize Time Synchronization' },
    { id: '8.5', group: '8. Audit Log Management', title: 'Collect Detailed Audit Logs', description: 'Collect Detailed Audit Logs' },
    { id: '8.6', group: '8. Audit Log Management', title: 'Collect DNS Query Audit Logs', description: 'Collect DNS Query Audit Logs' },
    { id: '8.7', group: '8. Audit Log Management', title: 'Collect URL Request Audit Logs', description: 'Collect URL Request Audit Logs' },
    { id: '8.8', group: '8. Audit Log Management', title: 'Collect Command-Line Audit Logs', description: 'Collect Command-Line Audit Logs' },
    { id: '8.9', group: '8. Audit Log Management', title: 'Centralize Audit Logs', description: 'Centralize Audit Logs' },
    { id: '8.10', group: '8. Audit Log Management', title: 'Retain Audit Logs', description: 'Retain Audit Logs' },
    { id: '8.11', group: '8. Audit Log Management', title: 'Conduct Audit Log Reviews', description: 'Conduct Audit Log Reviews' },
    { id: '8.12', group: '8. Audit Log Management', title: 'Collect Service Provider Logs', description: 'Collect Service Provider Logs' },
    { id: '9.1', group: '9. Email and Web Browser Protections', title: 'Ensure Use of Only Fully Supported Browsers and Email Clients', description: 'Ensure Use of Only Fully Supported Browsers and Email Clients' },
    { id: '9.2', group: '9. Email and Web Browser Protections', title: 'Use DNS Filtering Services', description: 'Use DNS Filtering Services' },
    { id: '9.3', group: '9. Email and Web Browser Protections', title: 'Maintain and Enforce Network-Based URL Filters', description: 'Maintain and Enforce Network-Based URL Filters' },
    { id: '9.4', group: '9. Email and Web Browser Protections', title: 'Restrict Unnecessary or Unauthorized Browser and Email Client Extensions', description: 'Restrict Unnecessary or Unauthorized Browser and Email Client Extensions' },
    { id: '9.5', group: '9. Email and Web Browser Protections', title: 'Implement DMARC', description: 'Implement DMARC' },
    { id: '9.6', group: '9. Email and Web Browser Protections', title: 'Block Unnecessary File Types', description: 'Block Unnecessary File Types' },
    { id: '9.7', group: '9. Email and Web Browser Protections', title: 'Deploy and Maintain Email Server Anti-Malware Protections', description: 'Deploy and Maintain Email Server Anti-Malware Protections' },
    { id: '10.1', group: '10. Malware Defenses', title: 'Deploy and Maintain Anti-Malware Software', description: 'Deploy and Maintain Anti-Malware Software' },
    { id: '10.2', group: '10. Malware Defenses', title: 'Configure Automatic Anti-Malware Signature Updates', description: 'Configure Automatic Anti-Malware Signature Updates' },
    { id: '10.3', group: '10. Malware Defenses', title: 'Disable Autorun and Autoplay for Removable Media', description: 'Disable Autorun and Autoplay for Removable Media' },
    { id: '10.4', group: '10. Malware Defenses', title: 'Configure Automatic Anti-Malware Scanning of Removable Media', description: 'Configure Automatic Anti-Malware Scanning of Removable Media' },
    { id: '10.5', group: '10. Malware Defenses', title: 'Enable Anti-Exploitation Features', description: 'Enable Anti-Exploitation Features' },
    { id: '10.6', group: '10. Malware Defenses', title: 'Centrally Manage Anti-Malware Software', description: 'Centrally Manage Anti-Malware Software' },
    { id: '10.7', group: '10. Malware Defenses', title: 'Use Behavior-Based Anti-Malware Software', description: 'Use Behavior-Based Anti-Malware Software' },
    { id: '11.1', group: '11. Data Recovery', title: 'Establish and Maintain a Data Recovery Process', description: 'Establish and Maintain a Data Recovery Process' },
    { id: '11.2', group: '11. Data Recovery', title: 'Perform Automated Backups', description: 'Perform Automated Backups' },
    { id: '11.3', group: '11. Data Recovery', title: 'Protect Recovery Data', description: 'Protect Recovery Data' },
    { id: '11.4', group: '11. Data Recovery', title: 'Establish and Maintain an Isolated Instance of Recovery Data', description: 'Establish and Maintain an Isolated Instance of Recovery Data' },
    { id: '11.5', group: '11. Data Recovery', title: 'Test Data Recovery', description: 'Test Data Recovery' },
    { id: '12.1', group: '12. Network Infrastructure Management', title: 'Ensure Network Infrastructure is Up-to-Date', description: 'Ensure Network Infrastructure is Up-to-Date' },
    { id: '12.2', group: '12. Network Infrastructure Management', title: 'Establish and Maintain a Secure Network Architecture', description: 'Establish and Maintain a Secure Network Architecture' },
    { id: '12.3', group: '12. Network Infrastructure Management', title: 'Securely Manage Network Infrastructure', description: 'Securely Manage Network Infrastructure' },
    { id: '12.4', group: '12. Network Infrastructure Management', title: 'Establish and Maintain Architecture Diagrams', description: 'Establish and Maintain Architecture Diagrams' },
    { id: '12.5', group: '12. Network Infrastructure Management', title: 'Centralize Network Authentication, Authorization, and Auditing (AAA)', description: 'Centralize Network Authentication, Authorization, and Auditing (AAA)' },
    { id: '12.6', group: '12. Network Infrastructure Management', title: 'Use of Secure Network Management and Communication Protocols', description: 'Use of Secure Network Management and Communication Protocols' },
    { id: '12.7', group: '12. Network Infrastructure Management', title: 'Ensure Remote Devices Utilize a VPN and are Connecting to an Enterprise\'s AAA Infrastructure', description: 'Ensure Remote Devices Utilize a VPN and are Connecting to an Enterprise\'s AAA Infrastructure' },
    { id: '12.8', group: '12. Network Infrastructure Management', title: 'Establish and Maintain Dedicated Computing Resources for All Administrative Work', description: 'Establish and Maintain Dedicated Computing Resources for All Administrative Work' },
    { id: '13.1', group: '13. Network Monitoring and Defense', title: 'Centralize Security Event Alerting', description: 'Centralize Security Event Alerting' },
    { id: '13.2', group: '13. Network Monitoring and Defense', title: 'Deploy a Host-Based Intrusion Detection Solution', description: 'Deploy a Host-Based Intrusion Detection Solution' },
    { id: '13.3', group: '13. Network Monitoring and Defense', title: 'Deploy a Network Intrusion Detection Solution', description: 'Deploy a Network Intrusion Detection Solution' },
    { id: '13.4', group: '13. Network Monitoring and Defense', title: 'Perform Traffic Filtering Between Network Segments', description: 'Perform Traffic Filtering Between Network Segments' },
    { id: '13.5', group: '13. Network Monitoring and Defense', title: 'Manage Access Control for Remote Assets', description: 'Manage Access Control for Remote Assets' },
    { id: '13.6', group: '13. Network Monitoring and Defense', title: 'Collect Network Traffic Flow Logs', description: 'Collect Network Traffic Flow Logs' },
    { id: '13.7', group: '13. Network Monitoring and Defense', title: 'Deploy a Host-Based Intrusion Prevention Solution', description: 'Deploy a Host-Based Intrusion Prevention Solution' },
    { id: '13.8', group: '13. Network Monitoring and Defense', title: 'Deploy a Network Intrusion Prevention Solution', description: 'Deploy a Network Intrusion Prevention Solution' },
    { id: '13.9', group: '13. Network Monitoring and Defense', title: 'Deploy Port-Level Access Control', description: 'Deploy Port-Level Access Control' },
    { id: '13.10', group: '13. Network Monitoring and Defense', title: 'Perform Application Layer Filtering', description: 'Perform Application Layer Filtering' },
    { id: '13.11', group: '13. Network Monitoring and Defense', title: 'Tune Security Event Alerting Thresholds', description: 'Tune Security Event Alerting Thresholds' },
    { id: '14.1', group: '14. Security Awareness and Skills Training', title: 'Establish and Maintain a Security Awareness Program', description: 'Establish and Maintain a Security Awareness Program' },
    { id: '14.2', group: '14. Security Awareness and Skills Training', title: 'Train Workforce Members to Recognize Social Engineering Attacks', description: 'Train Workforce Members to Recognize Social Engineering Attacks' },
    { id: '14.3', group: '14. Security Awareness and Skills Training', title: 'Train Workforce Members on Authentication Best Practices', description: 'Train Workforce Members on Authentication Best Practices' },
    { id: '14.4', group: '14. Security Awareness and Skills Training', title: 'Train Workforce on Data Handling Best Practices', description: 'Train Workforce on Data Handling Best Practices' },
    { id: '14.5', group: '14. Security Awareness and Skills Training', title: 'Train Workforce Members on Causes of Unintentional Data Exposure', description: 'Train Workforce Members on Causes of Unintentional Data Exposure' },
    { id: '14.6', group: '14. Security Awareness and Skills Training', title: 'Train Workforce Members on Recognizing and Reporting Security Incidents', description: 'Train Workforce Members on Recognizing and Reporting Security Incidents' },
    { id: '14.7', group: '14. Security Awareness and Skills Training', title: 'Train Workforce on How to Identify and Report if Their Enterprise Assets are Missing Security Updates', description: 'Train Workforce on How to Identify and Report if Their Enterprise Assets are Missing Security Updates' },
    { id: '14.8', group: '14. Security Awareness and Skills Training', title: 'Train Workforce on the Dangers of Connecting to and Transmitting Data Over Insecure Networks', description: 'Train Workforce on the Dangers of Connecting to and Transmitting Data Over Insecure Networks' },
    { id: '14.9', group: '14. Security Awareness and Skills Training', title: 'Conduct Security Awareness and Skills Training on Recognizing and Reporting Security Incidents', description: 'Conduct Security Awareness and Skills Training on Recognizing and Reporting Security Incidents' },
    { id: '15.1', group: '15. Service Provider Management', title: 'Establish and Maintain an Inventory of Service Providers', description: 'Establish and Maintain an Inventory of Service Providers' },
    { id: '15.2', group: '15. Service Provider Management', title: 'Establish and Maintain a Service Provider Management Policy', description: 'Establish and Maintain a Service Provider Management Policy' },
    { id: '15.3', group: '15. Service Provider Management', title: 'Classify Service Providers', description: 'Classify Service Providers' },
    { id: '15.4', group: '15. Service Provider Management', title: 'Ensure Service Provider Contracts Include Security Requirements', description: 'Ensure Service Provider Contracts Include Security Requirements' },
    { id: '15.5', group: '15. Service Provider Management', title: 'Assess Service Providers', description: 'Assess Service Providers' },
    { id: '15.6', group: '15. Service Provider Management', title: 'Monitor Service Providers', description: 'Monitor Service Providers' },
    { id: '15.7', group: '15. Service Provider Management', title: 'Securely Decommission Service Providers', description: 'Securely Decommission Service Providers' },
    { id: '16.1', group: '16. Application Software Security', title: 'Establish and Maintain a Secure Application Development Process', description: 'Establish and Maintain a Secure Application Development Process' },
    { id: '16.2', group: '16. Application Software Security', title: 'Establish and Maintain a Process to Accept and Address Software Vulnerabilities', description: 'Establish and Maintain a Process to Accept and Address Software Vulnerabilities' },
    { id: '16.3', group: '16. Application Software Security', title: 'Perform Root Cause Analysis on Security Vulnerabilities', description: 'Perform Root Cause Analysis on Security Vulnerabilities' },
    { id: '16.4', group: '16. Application Software Security', title: 'Establish and Manage an Inventory of Third-Party Software Components', description: 'Establish and Manage an Inventory of Third-Party Software Components' },
    { id: '16.5', group: '16. Application Software Security', title: 'Use Up-to-Date and Trusted Third-Party Software Components', description: 'Use Up-to-Date and Trusted Third-Party Software Components' },
    { id: '16.6', group: '16. Application Software Security', title: 'Establish and Maintain a Severity Rating System and Process for Application Vulnerabilities', description: 'Establish and Maintain a Severity Rating System and Process for Application Vulnerabilities' },
    { id: '16.7', group: '16. Application Software Security', title: 'Use Standard Hardening Configuration Templates for Application Infrastructure', description: 'Use Standard Hardening Configuration Templates for Application Infrastructure' },
    { id: '16.8', group: '16. Application Software Security', title: 'Separate Production and Non-Production Systems', description: 'Separate Production and Non-Production Systems' },
    { id: '16.9', group: '16. Application Software Security', title: 'Train Developers in Application Security Concepts and Secure Coding', description: 'Train Developers in Application Security Concepts and Secure Coding' },
    { id: '16.10', group: '16. Application Software Security', title: 'Apply Secure Design Principles in Application Architectures', description: 'Apply Secure Design Principles in Application Architectures' },
    { id: '16.11', group: '16. Application Software Security', title: 'Leverage Vetted Modules or Services for Application Security Components', description: 'Leverage Vetted Modules or Services for Application Security Components' },
    { id: '16.12', group: '16. Application Software Security', title: 'Implement Code-Level Security Checks', description: 'Implement Code-Level Security Checks' },
    { id: '16.13', group: '16. Application Software Security', title: 'Conduct Application Penetration Testing', description: 'Conduct Application Penetration Testing' },
    { id: '16.14', group: '16. Application Software Security', title: 'Conduct Threat Modeling', description: 'Conduct Threat Modeling' },
    { id: '17.1', group: '17. Incident Response Management', title: 'Designate Personnel to Manage Incident Handling', description: 'Designate Personnel to Manage Incident Handling' },
    { id: '17.2', group: '17. Incident Response Management', title: 'Establish and Maintain Contact Information for Reporting Security Incidents', description: 'Establish and Maintain Contact Information for Reporting Security Incidents' },
    { id: '17.3', group: '17. Incident Response Management', title: 'Establish and Maintain an Enterprise Process for Reporting Incidents', description: 'Establish and Maintain an Enterprise Process for Reporting Incidents' },
    { id: '17.4', group: '17. Incident Response Management', title: 'Establish and Maintain an Incident Response Process', description: 'Establish and Maintain an Incident Response Process' },
    { id: '17.5', group: '17. Incident Response Management', title: 'Assign Key Roles and Responsibilities', description: 'Assign Key Roles and Responsibilities' },
    { id: '17.6', group: '17. Incident Response Management', title: 'Define Mechanisms for Communicating During Incident Response', description: 'Define Mechanisms for Communicating During Incident Response' },
    { id: '17.7', group: '17. Incident Response Management', title: 'Conduct Routine Incident Response Exercises', description: 'Conduct Routine Incident Response Exercises' },
    { id: '17.8', group: '17. Incident Response Management', title: 'Conduct Post-Incident Reviews', description: 'Conduct Post-Incident Reviews' },
    { id: '17.9', group: '17. Incident Response Management', title: 'Establish and Maintain Security Incident Thresholds', description: 'Establish and Maintain Security Incident Thresholds' },
    { id: '18.1', group: '18. Penetration Testing', title: 'Establish and Maintain a Penetration Testing Program', description: 'Establish and Maintain a Penetration Testing Program' },
    { id: '18.2', group: '18. Penetration Testing', title: 'Perform Periodic External Penetration Tests', description: 'Perform Periodic External Penetration Tests' },
    { id: '18.3', group: '18. Penetration Testing', title: 'Remediate Penetration Test Findings', description: 'Remediate Penetration Test Findings' },
    { id: '18.4', group: '18. Penetration Testing', title: 'Validate Penetration Testing', description: 'Validate Penetration Testing' },
    { id: '18.5', group: '18. Penetration Testing', title: 'Perform Periodic Internal Penetration Tests', description: 'Perform Periodic Internal Penetration Tests' },
  ],
  'PCI DSS v4.0': [
    { id: '1.1', group: '1. Install and Maintain Network Security Controls', title: 'Processes and mechanisms for installing and maintaining network security controls are defined and understood.', description: 'Processes and mechanisms for installing and maintaining network security controls are defined and understood.' },
    { id: '1.2', group: '1. Install and Maintain Network Security Controls', title: 'Network security controls (NSCs) are configured and maintained.', description: 'Network security controls (NSCs) are configured and maintained.' },
    { id: '1.3', group: '1. Install and Maintain Network Security Controls', title: 'Network access to and from the cardholder data environment is restricted.', description: 'Network access to and from the cardholder data environment is restricted.' },
    { id: '1.4', group: '1. Install and Maintain Network Security Controls', title: 'Network connections between trusted and untrusted networks are controlled.', description: 'Network connections between trusted and untrusted networks are controlled.' },
    { id: '1.5', group: '1. Install and Maintain Network Security Controls', title: 'Risks to the CDE from computing devices that are able to connect to both untrusted networks and the CDE are mitigated.', description: 'Risks to the CDE from computing devices that are able to connect to both untrusted networks and the CDE are mitigated.' },
    { id: '2.1', group: '2. Apply Secure Configurations to All System Components', title: 'Processes and mechanisms for applying secure configurations to all system components are defined and understood.', description: 'Processes and mechanisms for applying secure configurations to all system components are defined and understood.' },
    { id: '2.2', group: '2. Apply Secure Configurations to All System Components', title: 'System components are configured and managed securely.', description: 'System components are configured and managed securely.' },
    { id: '2.3', group: '2. Apply Secure Configurations to All System Components', title: 'Wireless environments are configured and managed securely.', description: 'Wireless environments are configured and managed securely.' },
    { id: '3.1', group: '3. Protect Stored Account Data', title: 'Processes and mechanisms for protecting stored account data are defined and understood.', description: 'Processes and mechanisms for protecting stored account data are defined and understood.' },
    { id: '3.2', group: '3. Protect Stored Account Data', title: 'Storage of account data is kept to a minimum.', description: 'Storage of account data is kept to a minimum.' },
    { id: '3.3', group: '3. Protect Stored Account Data', title: 'Sensitive authentication data (SAD) is not stored after authorization.', description: 'Sensitive authentication data (SAD) is not stored after authorization.' },
    { id: '3.4', group: '3. Protect Stored Account Data', title: 'Access to displays of full PAN and ability to copy account data is restricted.', description: 'Access to displays of full PAN and ability to copy account data is restricted.' },
    { id: '3.5', group: '3. Protect Stored Account Data', title: 'Primary account number (PAN) is secured wherever it is stored.', description: 'Primary account number (PAN) is secured wherever it is stored.' },
    { id: '3.6', group: '3. Protect Stored Account Data', title: 'Cryptographic keys used to protect stored account data are secured.', description: 'Cryptographic keys used to protect stored account data are secured.' },
    { id: '3.7', group: '3. Protect Stored Account Data', title: 'Where cryptography is used to protect stored account data, key management processes and procedures covering all aspects of the key lifecycle are defined and implemented.', description: 'Where cryptography is used to protect stored account data, key management processes and procedures covering all aspects of the key lifecycle are defined and implemented.' },
    { id: '4.1', group: '4. Protect Transmitted Data', title: 'Processes and mechanisms for protecting account data with strong cryptography during transmission over open, public networks are defined and understood.', description: 'Processes and mechanisms for protecting account data with strong cryptography during transmission over open, public networks are defined and understood.' },
    { id: '4.2', group: '4. Protect Transmitted Data', title: 'PAN is protected with strong cryptography during transmission.', description: 'PAN is protected with strong cryptography during transmission.' },
    { id: '5.1', group: '5. Protect All Systems and Networks from Malicious Software', title: 'Processes and mechanisms for protecting all systems and networks from malicious software are defined and understood.', description: 'Processes and mechanisms for protecting all systems and networks from malicious software are defined and understood.' },
    { id: '5.2', group: '5. Protect All Systems and Networks from Malicious Software', title: 'Malicious software (malware) is prevented, or detected and addressed.', description: 'Malicious software (malware) is prevented, or detected and addressed.' },
    { id: '5.3', group: '5. Protect All Systems and Networks from Malicious Software', title: 'Anti-malware mechanisms and processes are active, maintained, and monitored.', description: 'Anti-malware mechanisms and processes are active, maintained, and monitored.' },
    { id: '6.1', group: '6. Develop and Maintain Secure Systems and Software', title: 'Processes and mechanisms for developing and maintaining secure systems and software are defined and understood.', description: 'Processes and mechanisms for developing and maintaining secure systems and software are defined and understood.' },
    { id: '6.2', group: '6. Develop and Maintain Secure Systems and Software', title: 'Bespoke and custom software are developed securely.', description: 'Bespoke and custom software are developed securely.' },
    { id: '6.3', group: '6. Develop and Maintain Secure Systems and Software', title: 'Security vulnerabilities are identified and addressed.', description: 'Security vulnerabilities are identified and addressed.' },
    { id: '6.4', group: '6. Develop and Maintain Secure Systems and Software', title: 'Public-facing web applications are protected against attacks.', description: 'Public-facing web applications are protected against attacks.' },
    { id: '6.5', group: '6. Develop and Maintain Secure Systems and Software', title: 'Changes to all system components are managed securely.', description: 'Changes to all system components are managed securely.' },
    { id: '7.1', group: '7. Restrict Access to System Components and Cardholder Data by Business Need to Know', title: 'Processes and mechanisms for restricting access to system components and cardholder data by business need to know are defined and understood.', description: 'Processes and mechanisms for restricting access to system components and cardholder data by business need to know are defined and understood.' },
    { id: '7.2', group: '7. Restrict Access to System Components and Cardholder Data by Business Need to Know', title: 'Access to system components and data is appropriately defined and assigned.', description: 'Access to system components and data is appropriately defined and assigned.' },
    { id: '7.3', group: '7. Restrict Access to System Components and Cardholder Data by Business Need to Know', title: 'Access to system components and data is managed via an access control system.', description: 'Access to system components and data is managed via an access control system.' },
    { id: '8.1', group: '8. Identify Users and Authenticate Access to System Components', title: 'Processes and mechanisms for identifying users and authenticating access to system components are defined and understood.', description: 'Processes and mechanisms for identifying users and authenticating access to system components are defined and understood.' },
    { id: '8.2', group: '8. Identify Users and Authenticate Access to System Components', title: 'User identification and related accounts for users and administrators are strictly managed throughout an account’s lifecycle.', description: 'User identification and related accounts for users and administrators are strictly managed throughout an account’s lifecycle.' },
    { id: '8.3', group: '8. Identify Users and Authenticate Access to System Components', title: 'Strong authentication for users and administrators is established and managed.', description: 'Strong authentication for users and administrators is established and managed.' },
    { id: '8.4', group: '8. Identify Users and Authenticate Access to System Components', title: 'Multi-factor authentication (MFA) is implemented to secure access into the CDE.', description: 'Multi-factor authentication (MFA) is implemented to secure access into the CDE.' },
    { id: '8.5', group: '8. Identify Users and Authenticate Access to System Components', title: 'Multi-factor authentication (MFA) systems are configured to prevent misuse.', description: 'Multi-factor authentication (MFA) systems are configured to prevent misuse.' },
    { id: '8.6', group: '8. Identify Users and Authenticate Access to System Components', title: 'Use of application and system accounts and associated authentication factors is strictly managed.', description: 'Use of application and system accounts and associated authentication factors is strictly managed.' },
    { id: '9.1', group: '9. Restrict Physical Access to Cardholder Data', title: 'Processes and mechanisms for restricting physical access to cardholder data are defined and understood.', description: 'Processes and mechanisms for restricting physical access to cardholder data are defined and understood.' },
    { id: '9.2', group: '9. Restrict Physical Access to Cardholder Data', title: 'Physical access controls manage entry into facilities with systems that store, process, or transmit cardholder data.', description: 'Physical access controls manage entry into facilities with systems that store, process, or transmit cardholder data.' },
    { id: '9.3', group: '9. Restrict Physical Access to Cardholder Data', title: 'Physical access for personnel and visitors is authorized and managed.', description: 'Physical access for personnel and visitors is authorized and managed.' },
    { id: '9.4', group: '9. Restrict Physical Access to Cardholder Data', title: 'Media with cardholder data is securely stored, accessed, distributed, and destroyed.', description: 'Media with cardholder data is securely stored, accessed, distributed, and destroyed.' },
    { id: '9.5', group: '9. Restrict Physical Access to Cardholder Data', title: 'Point of interaction (POI) devices are protected from tampering and unauthorized substitution.', description: 'Point of interaction (POI) devices are protected from tampering and unauthorized substitution.' },
    { id: '10.1', group: '10. Log and Monitor All Access to System Components and Cardholder Data', title: 'Processes and mechanisms for logging and monitoring all access to system components and cardholder data are defined and understood.', description: 'Processes and mechanisms for logging and monitoring all access to system components and cardholder data are defined and understood.' },
    { id: '10.2', group: '10. Log and Monitor All Access to System Components and Cardholder Data', title: 'Audit logs are implemented to support the detection of anomalies and suspicious activities, and the forensic analysis of events.', description: 'Audit logs are implemented to support the detection of anomalies and suspicious activities, and the forensic analysis of events.' },
    { id: '10.3', group: '10. Log and Monitor All Access to System Components and Cardholder Data', title: 'Audit logs are protected from destruction and unauthorized modifications.', description: 'Audit logs are protected from destruction and unauthorized modifications.' },
    { id: '10.4', group: '10. Log and Monitor All Access to System Components and Cardholder Data', title: 'Audit logs are reviewed to identify anomalies or suspicious activity.', description: 'Audit logs are reviewed to identify anomalies or suspicious activity.' },
    { id: '10.5', group: '10. Log and Monitor All Access to System Components and Cardholder Data', title: 'Audit log history is retained and available for analysis.', description: 'Audit log history is retained and available for analysis.' },
    { id: '10.6', group: '10. Log and Monitor All Access to System Components and Cardholder Data', title: 'Time-synchronization mechanisms support consistent time settings across all systems.', description: 'Time-synchronization mechanisms support consistent time settings across all systems.' },
    { id: '10.7', group: '10. Log and Monitor All Access to System Components and Cardholder Data', title: 'Failures of critical security control systems are detected, reported, and responded to promptly.', description: 'Failures of critical security control systems are detected, reported, and responded to promptly.' },
    { id: '11.1', group: '11. Test Security of Systems and Networks Regularly', title: 'Processes and mechanisms for regularly testing security of systems and networks are defined and understood.', description: 'Processes and mechanisms for regularly testing security of systems and networks are defined and understood.' },
    { id: '11.2', group: '11. Test Security of Systems and Networks Regularly', title: 'Wireless access points are identified and monitored, and unauthorized wireless access points are addressed.', description: 'Wireless access points are identified and monitored, and unauthorized wireless access points are addressed.' },
    { id: '11.3', group: '11. Test Security of Systems and Networks Regularly', title: 'External and internal vulnerabilities are regularly identified, prioritized, and addressed.', description: 'External and internal vulnerabilities are regularly identified, prioritized, and addressed.' },
    { id: '11.4', group: '11. Test Security of Systems and Networks Regularly', title: 'External and internal penetration testing is regularly performed, and exploitable vulnerabilities and security weaknesses are corrected.', description: 'External and internal penetration testing is regularly performed, and exploitable vulnerabilities and security weaknesses are corrected.' },
    { id: '11.5', group: '11. Test Security of Systems and Networks Regularly', title: 'Network intrusions and unexpected file changes are detected and responded to.', description: 'Network intrusions and unexpected file changes are detected and responded to.' },
    { id: '12.1', group: '12. Support Information Security with Organizational Policies and Programs', title: 'A comprehensive information security policy that governs and provides direction for protection of the entity’s information assets is known and current.', description: 'A comprehensive information security policy that governs and provides direction for protection of the entity’s information assets is known and current.' },
    { id: '12.2', group: '12. Support Information Security with Organizational Policies and Programs', title: 'Acceptable use policies for end-user technologies are defined and implemented.', description: 'Acceptable use policies for end-user technologies are defined and implemented.' },
    { id: '12.3', group: '12. Support Information Security with Organizational Policies and Programs', title: 'Risks to the cardholder data environment are identified and managed.', description: 'Risks to the cardholder data environment are identified and managed.' },
    { id: '12.4', group: '12. Support Information Security with Organizational Policies and Programs', title: 'PCI DSS compliance is managed.', description: 'PCI DSS compliance is managed.' },
    { id: '12.5', group: '12. Support Information Security with Organizational Policies and Programs', title: 'PCI DSS scope is documented and validated.', description: 'PCI DSS scope is documented and validated.' },
    { id: '12.6', group: '12. Support Information Security with Organizational Policies and Programs', title: 'Security awareness education is an ongoing activity.', description: 'Security awareness education is an ongoing activity.' },
    { id: '12.7', group: '12. Support Information Security with Organizational Policies and Programs', title: 'Personnel who have access to the CDE are screened to minimize the risk of attacks from internal sources.', description: 'Personnel who have access to the CDE are screened to minimize the risk of attacks from internal sources.' },
    { id: '12.8', group: '12. Support Information Security with Organizational Policies and Programs', title: 'Risk to information assets associated with third-party service provider (TPSP) relationships is managed.', description: 'Risk to information assets associated with third-party service provider (TPSP) relationships is managed.' },
    { id: '12.9', group: '12. Support Information Security with Organizational Policies and Programs', title: 'TPSPs that support customers\' PCI DSS compliance provide assurance of their PCI DSS compliance status.', description: 'TPSPs that support customers\' PCI DSS compliance provide assurance of their PCI DSS compliance status.' },
    { id: '12.10', group: '12. Support Information Security with Organizational Policies and Programs', title: 'Suspected and confirmed security incidents that could impact the CDE are responded to immediately.', description: 'Suspected and confirmed security incidents that could impact the CDE are responded to immediately.' },
  ],
  'SOC 2 Type 2': [
    { id: 'CC1.1', group: 'Control Environment', title: 'Integrity and Ethical Values', description: 'The entity demonstrates a commitment to integrity and ethical values.' },
    { id: 'CC1.2', group: 'Control Environment', title: 'Board of Directors Independence', description: 'The board of directors demonstrates independence from management and exercises oversight of the development and performance of internal control.' },
    { id: 'CC2.1', group: 'Communication', title: 'Information Quality', description: 'The entity obtains or generates and uses relevant, quality information to support the functioning of internal control.' },
    { id: 'CC3.1', group: 'Risk Assessment', title: 'Specify Objectives', description: 'The entity specifies objectives with sufficient clarity to enable the identification and assessment of risks relating to objectives.' }
  ]
};

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const DEMO_RISKS: Partial<Risk>[] = [
  {
    name: 'Phishing Attacks',
    description: 'Employees falling for sophisticated phishing emails leading to credential theft and unauthorized access.',
    likelihood: 'High',
    mitigations: 'Implement mandatory security awareness training, deploy advanced email filtering, and enforce MFA across all accounts.',
    owner: 'Security Operations'
  },
  {
    name: 'Unpatched Vulnerabilities',
    description: 'Critical production systems running outdated software with known exploits (CVEs).',
    likelihood: 'Critical',
    mitigations: 'Establish a formal patch management policy, perform weekly vulnerability scans, and automate patching for non-critical systems.',
    owner: 'IT Infrastructure'
  },
  {
    name: 'Insider Threat',
    description: 'Malicious or negligent actions by employees or contractors leading to data exfiltration.',
    likelihood: 'Medium',
    mitigations: 'Implement Data Loss Prevention (DLP) tools, enforce the principle of least privilege, and monitor privileged account activity.',
    owner: 'Compliance'
  },
  {
    name: 'Data Leakage via Cloud Storage',
    description: 'Sensitive customer data stored in misconfigured public S3 buckets or cloud storage.',
    likelihood: 'High',
    mitigations: 'Use cloud security posture management (CSPM) tools, conduct regular configuration audits, and disable public access by default.',
    owner: 'Cloud Engineering'
  },
  {
    name: 'Weak Password Policy',
    description: 'Use of easily guessable passwords across corporate accounts and lack of rotation.',
    likelihood: 'Medium',
    mitigations: 'Enforce strong password complexity requirements, implement a password manager, and transition to passwordless authentication where possible.',
    owner: 'Identity & Access Management'
  }
];

const DEMO_VULNERABILITIES: Partial<Vulnerability>[] = [
  {
    pluginId: '104743',
    pluginName: 'TLS Version 1.0 Protocol Detection',
    severity: 'Medium',
    host: '192.168.1.10',
    protocol: 'tcp',
    port: '443',
    description: 'The remote service accepts connections using TLS 1.0. TLS 1.0 has a number of cryptographic design flaws. Modern implementations of TLS 1.0 mitigate these problems, but newer versions of TLS like 1.2 and 1.3 are designed against these flaws and should be used whenever possible.',
    solution: 'Enable support for TLS 1.2 and/or 1.3, and disable support for TLS 1.0.',
    status: 'Open',
    firstSeen: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000).toISOString(), // 45 days ago
  },
  {
    pluginId: '156032',
    pluginName: 'Apache Log4j 2.x < 2.15.0-rc2 RCE (Log4Shell)',
    severity: 'Critical',
    host: '10.0.5.50',
    protocol: 'tcp',
    port: '8080',
    description: 'The version of Apache Log4j on the remote host is 2.x prior to 2.15.0-rc2. It is, therefore, affected by a remote code execution vulnerability due to a flaw in the JNDI features used in configuration, log messages, and parameters.',
    solution: 'Upgrade to Apache Log4j version 2.15.0 or later.',
    status: 'Open',
    firstSeen: new Date(Date.now() - 12 * 24 * 60 * 60 * 1000).toISOString(), // 12 days ago
  },
  {
    pluginId: '51192',
    pluginName: 'SSL Certificate Cannot Be Trusted',
    severity: 'Medium',
    host: '192.168.1.15',
    protocol: 'tcp',
    port: '8443',
    description: 'The server\'s X.509 certificate cannot be trusted. This situation can occur in three different ways, in which the chain of trust can be broken.',
    solution: 'Purchase or generate a proper SSL certificate for this service.',
    status: 'Open',
    firstSeen: new Date(Date.now() - 120 * 24 * 60 * 60 * 1000).toISOString(), // 120 days ago
  },
  {
    pluginId: '10881',
    pluginName: 'SSH Protocol Version 1 Supported',
    severity: 'High',
    host: '10.0.2.100',
    protocol: 'tcp',
    port: '22',
    description: 'The remote SSH daemon supports version 1 of the SSH protocol. The SSHv1 protocol has known cryptographic flaws and is considered deprecated.',
    solution: 'Configure the SSH daemon to only support SSHv2.',
    status: 'Open',
    firstSeen: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(), // 2 days ago
  },
  {
    pluginId: '11219',
    pluginName: 'Nessus SYN scanner',
    severity: 'Info',
    host: '192.168.1.10',
    protocol: 'tcp',
    port: '80',
    description: 'Port 80/tcp was found to be open.',
    solution: 'n/a',
    status: 'Open',
    firstSeen: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(), // 5 days ago
  }
];

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [isAuthReady, setIsAuthReady] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [activeTool, setActiveTool] = useState<'questionnaire' | 'controls' | 'resilience' | 'scorecard' | 'risk' | 'compliance' | 'pentest' | 'vulnerability' | 'settings'>('questionnaire');
  const [activeTab, setActiveTab] = useState<'dashboard' | 'kb' | 'questionnaires'>('dashboard');
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    if (typeof window !== 'undefined') {
      return (localStorage.getItem('theme') as 'light' | 'dark') || 'light';
    }
    return 'light';
  });
  const [kb, setKb] = useState<QAItem[]>([]);
  const [questionnaires, setQuestionnaires] = useState<Questionnaire[]>([]);
  const [risks, setRisks] = useState<Risk[]>([]);
  const [pentestResults, setPentestResults] = useState<PentestResult[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [isAddingQA, setIsAddingQA] = useState(false);
  const [isAddingRisk, setIsAddingRisk] = useState(false);
  const [isAddingPentest, setIsAddingPentest] = useState(false);
  const [editingRisk, setEditingRisk] = useState<Risk | null>(null);
  const [editingPentest, setEditingPentest] = useState<PentestResult | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [processingProgress, setProcessingProgress] = useState(0);
  const [globalError, setGlobalError] = useState<string | null>(null);
  const [newQA, setNewQA] = useState({ question: '', answer: '', category: 'General' });
  const [newRisk, setNewRisk] = useState<Partial<Risk>>({
    name: '',
    description: '',
    likelihood: 'Medium',
    mitigations: '',
    owner: ''
  });
  const [newPentest, setNewPentest] = useState<Partial<PentestResult>>({
    title: '',
    description: '',
    severity: 'Medium',
    status: 'Open',
    source: 'Internal',
    date: new Date().toISOString().split('T')[0],
    assignment: '',
    remediationPlan: ''
  });
  const [expandedKB, setExpandedKB] = useState<Record<string, boolean>>({});
  const [kbSearch, setKbSearch] = useState('');
  const kbFileInputRef = useRef<HTMLInputElement>(null);

  const [activeFramework, setActiveFramework] = useState<string>('NIST CSF 2.0');
  const [complianceStatuses, setComplianceStatuses] = useState<Record<string, Record<string, ComplianceStatus>>>({});
  const [complianceSearch, setComplianceSearch] = useState('');
  
  // Resilience Data State
  const [serverBackups, setServerBackups] = useState<any[]>([]);
  const [endUserBackups, setEndUserBackups] = useState<any[]>([]);
  const [drReplication, setDrReplication] = useState<any[]>([]);
  const [resilienceLoading, setResilienceLoading] = useState(false);

  // Integration Settings State
  const [veeamUrl, setVeeamUrl] = useState(() => localStorage.getItem('veeamUrl') || '');
  const [veeamToken, setVeeamToken] = useState(() => localStorage.getItem('veeamToken') || '');
  const [msTenantId, setMsTenantId] = useState(() => localStorage.getItem('msTenantId') || '');
  const [msClientId, setMsClientId] = useState(() => localStorage.getItem('msClientId') || '');
  const [msClientSecret, setMsClientSecret] = useState(() => localStorage.getItem('msClientSecret') || '');
  const [zertoUrl, setZertoUrl] = useState(() => localStorage.getItem('zertoUrl') || '');
  const [zertoToken, setZertoToken] = useState(() => localStorage.getItem('zertoToken') || '');

  // Security Controls State
  const [xdrData, setXdrData] = useState<any>(null);
  const [dlpData, setDlpData] = useState<any>(null);
  const [bitlockerData, setBitlockerData] = useState<any>(null);
  const [controlsLoading, setControlsLoading] = useState(false);

  // Scorecard State
  const [scorecardDomain, setScorecardDomain] = useState(() => localStorage.getItem('scorecardDomain') || '');
  const [scorecardData, setScorecardData] = useState<any>(null);
  const [isFetchingScorecard, setIsFetchingScorecard] = useState(false);
  const [scorecardError, setScorecardError] = useState<string | null>(null);

  // Authentication and Data Listeners
  useEffect(() => {
    const unsubscribeAuth = onAuthStateChanged(auth, (currentUser) => {
      setUser(currentUser);
      setIsAuthReady(true);
    });

    const checkRedirect = async () => {
      try {
        const result = await getRedirectResult(auth);
        if (result?.user) {
          setUser(result.user);
        }
      } catch (error: any) {
        console.error('Redirect sign-in failed:', error);
        setLoginError(error.message || 'Failed to complete sign-in after redirect.');
      }
    };
    checkRedirect();

    return () => unsubscribeAuth();
  }, []);

  useEffect(() => {
    if (!user) {
      setKb([]);
      setQuestionnaires([]);
      setRisks([]);
      setPentestResults([]);
      setVulnerabilities([]);
      setComplianceStatuses({});
      return;
    }

    // Knowledge Base Listener
    const kbQuery = query(collection(db, 'kb'), where('uid', '==', user.uid), orderBy('lastUpdated', 'desc'));
    const unsubscribeKb = onSnapshot(kbQuery, (snapshot) => {
      const items = snapshot.docs.map(doc => doc.data() as QAItem);
      setKb(items);
    }, (error) => handleFirestoreError(error, OperationType.LIST, 'kb'));

    // Questionnaires Listener
    const qQuery = query(collection(db, 'questionnaires'), where('uid', '==', user.uid), orderBy('createdAt', 'desc'));
    const unsubscribeQ = onSnapshot(qQuery, (snapshot) => {
      const items = snapshot.docs.map(doc => doc.data() as Questionnaire);
      setQuestionnaires(items);
    }, (error) => handleFirestoreError(error, OperationType.LIST, 'questionnaires'));

    // Risks Listener
    const riskQuery = query(collection(db, 'risks'), where('uid', '==', user.uid), orderBy('createdAt', 'desc'));
    const unsubscribeRisk = onSnapshot(riskQuery, (snapshot) => {
      const items = snapshot.docs.map(doc => doc.data() as Risk);
      setRisks(items);
    }, (error) => handleFirestoreError(error, OperationType.LIST, 'risks'));

    // Pentest Results Listener
    const pentestQuery = query(collection(db, 'pentest_results'), where('uid', '==', user.uid), orderBy('date', 'desc'));
    const unsubscribePentest = onSnapshot(pentestQuery, (snapshot) => {
      const items = snapshot.docs.map(doc => doc.data() as PentestResult);
      setPentestResults(items);
    }, (error) => handleFirestoreError(error, OperationType.LIST, 'pentest_results'));

    // Vulnerabilities Listener
    const vulnQuery = query(collection(db, 'vulnerabilities'), where('uid', '==', user.uid), orderBy('lastSeen', 'desc'));
    const unsubscribeVuln = onSnapshot(vulnQuery, (snapshot) => {
      const items = snapshot.docs.map(doc => doc.data() as Vulnerability);
      setVulnerabilities(items);
    }, (error) => handleFirestoreError(error, OperationType.LIST, 'vulnerabilities'));

    // Compliance Statuses Listener
    const complianceQuery = query(collection(db, 'compliance_statuses'), where('uid', '==', user.uid));
    const unsubscribeCompliance = onSnapshot(complianceQuery, (snapshot) => {
      const statuses: Record<string, Record<string, ComplianceStatus>> = {};
      snapshot.docs.forEach(doc => {
        const data = doc.data();
        if (!statuses[data.framework]) {
          statuses[data.framework] = {};
        }
        statuses[data.framework][data.controlId] = data.status as ComplianceStatus;
      });
      setComplianceStatuses(statuses);
    }, (error) => handleFirestoreError(error, OperationType.LIST, 'compliance_statuses'));

    return () => {
      unsubscribeKb();
      unsubscribeQ();
      unsubscribeRisk();
      unsubscribePentest();
      unsubscribeVuln();
      unsubscribeCompliance();
    };
  }, [user]);

  // Fetch security controls data when tab is active
  useEffect(() => {
    if (activeTool === 'controls') {
      const fetchControlsData = async () => {
        setControlsLoading(true);
        try {
          // Mock fetch for now, or actual API calls if they existed
          await new Promise(resolve => setTimeout(resolve, 800));
          
          setXdrData({
            activeThreats: 3,
            endpointsMonitored: 1245,
            isolatedDevices: 2,
            lastScan: '10 mins ago',
            status: 'Operational'
          });
          
          setDlpData({
            incidentsToday: 12,
            blockedTransfers: 8,
            activePolicies: 45,
            status: 'Operational'
          });
          
          setBitlockerData({
            compliantDevices: 1200,
            nonCompliantDevices: 45,
            encryptionRate: 96.3,
            status: 'Warning'
          });
        } catch (error) {
          console.error("Failed to fetch controls data:", error);
        } finally {
          setControlsLoading(false);
        }
      };
      
      fetchControlsData();
    }
  }, [activeTool]);

  // Fetch resilience data when tab is active
  useEffect(() => {
    if (activeTool === 'resilience') {
      const fetchResilienceData = async () => {
        setResilienceLoading(true);
        try {
          const [veeamRes, onedriveRes, zertoRes] = await Promise.all([
            fetch('/api/resilience/veeam'),
            fetch('/api/resilience/onedrive'),
            fetch('/api/resilience/zerto')
          ]);
          
          if (veeamRes.ok) setServerBackups(await veeamRes.json());
          if (onedriveRes.ok) setEndUserBackups(await onedriveRes.json());
          if (zertoRes.ok) setDrReplication(await zertoRes.json());
        } catch (error) {
          console.error("Failed to fetch resilience data:", error);
        } finally {
          setResilienceLoading(false);
        }
      };
      
      fetchResilienceData();
    }
  }, [activeTool]);

  const fetchScorecardData = async (domain: string) => {
    if (!domain) return;
    setIsFetchingScorecard(true);
    setScorecardError(null);
    try {
      const res = await fetch(`/api/scorecard?domain=${encodeURIComponent(domain)}`);
      
      // Check if response is JSON before parsing
      const contentType = res.headers.get("content-type");
      if (!res.ok) {
        if (contentType && contentType.includes("application/json")) {
          const data = await res.json();
          throw new Error(data.error || `Error ${res.status}: Failed to fetch scorecard data`);
        } else {
          const text = await res.text();
          throw new Error(`Server error (${res.status}): ${text.substring(0, 100)}`);
        }
      }

      if (contentType && contentType.includes("application/json")) {
        const data = await res.json();
        setScorecardData(data);
        localStorage.setItem('scorecardDomain', domain);
      } else {
        const text = await res.text();
        console.error("Non-JSON response received:", text.substring(0, 200));
        throw new Error(`Received non-JSON response from server. Content-Type: ${contentType}. Body starts with: ${text.substring(0, 50)}...`);
      }
    } catch (error: any) {
      console.error("Scorecard API Error:", error);
      setScorecardError(error.message);
    } finally {
      setIsFetchingScorecard(false);
    }
  };

  const complianceProgress = useMemo(() => {
    const frameworkData = FRAMEWORKS[activeFramework] || [];
    const total = frameworkData.length;
    const statuses = complianceStatuses[activeFramework] || {};
    
    const implemented = Object.values(statuses).filter(s => s === 'Implemented').length;
    const inProgress = Object.values(statuses).filter(s => s === 'In Progress').length;
    const notApplicable = Object.values(statuses).filter(s => s === 'Not Applicable').length;
    
    const applicableTotal = total - notApplicable;
    const percentage = applicableTotal === 0 ? (total === 0 ? 0 : 100) : Math.round((implemented / applicableTotal) * 100);
    
    return { total, implemented, inProgress, notApplicable, percentage };
  }, [complianceStatuses, activeFramework]);

  const filteredControls = useMemo(() => {
    const frameworkData = FRAMEWORKS[activeFramework] || [];
    if (!complianceSearch) return frameworkData;
    const lower = complianceSearch.toLowerCase();
    return frameworkData.filter(item => 
      item.id.toLowerCase().includes(lower) || 
      item.title.toLowerCase().includes(lower) || 
      item.description.toLowerCase().includes(lower) ||
      item.group.toLowerCase().includes(lower)
    );
  }, [complianceSearch, activeFramework]);

  const toolNames = {
    questionnaire: 'Q&A Robot',
    controls: 'Security Controls',
    resilience: 'Resilience',
    scorecard: 'Scorecard',
    risk: 'Risk Assessment',
    compliance: 'Compliance Tracker',
    pentest: 'Pentest Results',
    vulnerability: 'Vulnerability Mgmt',
    settings: 'Settings'
  };

  const toolIcons = {
    questionnaire: <ClipboardList className="w-5 h-5 opacity-50" />,
    controls: <ShieldCheck className="w-5 h-5 opacity-50" />,
    resilience: <Zap className="w-5 h-5 opacity-50" />,
    scorecard: <BarChart3 className="w-5 h-5 opacity-50" />,
    risk: <Activity className="w-5 h-5 opacity-50" />,
    compliance: <Lock className="w-5 h-5 opacity-50" />,
    pentest: <Bug className="w-5 h-5 opacity-50" />,
    vulnerability: <Radar className="w-5 h-5 opacity-50" />,
    settings: <Settings className="w-5 h-5 opacity-50" />
  };

  useEffect(() => {
    localStorage.setItem('theme', theme);
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [theme]);

  // Save integration settings
  useEffect(() => {
    localStorage.setItem('veeamUrl', veeamUrl);
    localStorage.setItem('veeamToken', veeamToken);
    localStorage.setItem('msTenantId', msTenantId);
    localStorage.setItem('msClientId', msClientId);
    localStorage.setItem('msClientSecret', msClientSecret);
    localStorage.setItem('zertoUrl', zertoUrl);
    localStorage.setItem('zertoToken', zertoToken);
  }, [veeamUrl, veeamToken, msTenantId, msClientId, msClientSecret, zertoUrl, zertoToken]);

  const handleLogin = async () => {
    setLoginError(null);
    try {
      // Try popup first as it's more reliable in iframes/previews
      await signInWithPopup(auth, googleProvider);
    } catch (error: any) {
      console.error('Login failed:', error);
      
      // If popup is blocked or fails, try redirect as fallback
      if (error.code === 'auth/popup-blocked' || error.code === 'auth/cancelled-popup-request') {
        try {
          await signInWithRedirect(auth, googleProvider);
        } catch (redirError: any) {
          setLoginError(redirError.message || 'An unknown error occurred during sign in.');
        }
      } else {
        setLoginError(error.message || 'An unknown error occurred during sign in.');
      }
    }
  };

  const handleLogout = async () => {
    try {
      await signOut(auth);
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  const handleKBFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    
    if (file.name.endsWith('.xlsx') || file.name.endsWith('.xls') || file.name.endsWith('.csv')) {
      reader.onload = (e) => {
        const data = new Uint8Array(e.target?.result as ArrayBuffer);
        const workbook = XLSX.read(data, { type: 'array' });
        const sheetName = workbook.SheetNames[0];
        const worksheet = workbook.Sheets[sheetName];
        const json = XLSX.utils.sheet_to_json(worksheet, { header: 1 }) as any[][];
        
        // Assume first column is question, second is answer
        const newItems: QAItem[] = json.slice(1).map(row => {
          if (row[0] && row[1]) {
            return {
              id: crypto.randomUUID(),
              uid: user?.uid || '',
              question: String(row[0]),
              answer: String(row[1]),
              category: String(row[2] || 'Imported'),
              lastUpdated: new Date().toISOString()
            };
          }
          return null;
        }).filter(item => item !== null) as QAItem[];
        
        // Batch upload to Firestore
        newItems.forEach(async (item) => {
          try {
            await setDoc(doc(db, 'kb', item.id), item);
          } catch (error) {
            handleFirestoreError(error, OperationType.CREATE, `kb/${item.id}`);
          }
        });
      };
      reader.readAsArrayBuffer(file);
    } else if (file.name.endsWith('.docx')) {
      reader.onload = async (e) => {
        const arrayBuffer = e.target?.result as ArrayBuffer;
        const result = await mammoth.extractRawText({ arrayBuffer });
        const text = result.value;
        
        // For Word, we'll just add the whole text as a single entry for now
        // or try to split by some delimiter if possible.
        // Let's just add it as a "Document" entry.
        const item: QAItem = {
          id: crypto.randomUUID(),
          uid: user?.uid || '',
          question: `Document: ${file.name}`,
          answer: text,
          category: 'Document',
          lastUpdated: new Date().toISOString()
        };
        try {
          await setDoc(doc(db, 'kb', item.id), item);
        } catch (error) {
          handleFirestoreError(error, OperationType.CREATE, `kb/${item.id}`);
        }
      };
      reader.readAsArrayBuffer(file);
    } else if (file.name.endsWith('.pdf')) {
      reader.onload = async (e) => {
        const arrayBuffer = e.target?.result as ArrayBuffer;
        const loadingTask = pdfjs.getDocument(arrayBuffer);
        const pdf = await loadingTask.promise;
        let fullText = "";
        
        for (let i = 1; i <= pdf.numPages; i++) {
          const page = await pdf.getPage(i);
          const textContent = await page.getTextContent();
          const pageText = textContent.items.map((item: any) => item.str).join(" ");
          fullText += pageText + "\n";
        }
        
        const item: QAItem = {
          id: crypto.randomUUID(),
          uid: user?.uid || '',
          question: `PDF: ${file.name}`,
          answer: fullText,
          category: 'Document',
          lastUpdated: new Date().toISOString()
        };
        try {
          await setDoc(doc(db, 'kb', item.id), item);
        } catch (error) {
          handleFirestoreError(error, OperationType.CREATE, `kb/${item.id}`);
        }
      };
      reader.readAsArrayBuffer(file);
    }
    
    // Reset file input
    if (kbFileInputRef.current) kbFileInputRef.current.value = '';
  };

  const handleAddQA = async () => {
    if (!newQA.question || !newQA.answer || !user) return;
    const item: QAItem = {
      id: crypto.randomUUID(),
      uid: user.uid,
      ...newQA,
      lastUpdated: new Date().toISOString()
    };
    try {
      await setDoc(doc(db, 'kb', item.id), item);
      setNewQA({ question: '', answer: '', category: 'General' });
      setIsAddingQA(false);
    } catch (error) {
      handleFirestoreError(error, OperationType.CREATE, `kb/${item.id}`);
    }
  };

  const handleSeedDemoRisks = async () => {
    if (!user) return;
    setIsProcessing(true);
    try {
      const batch = writeBatch(db);
      DEMO_RISKS.forEach((risk) => {
        const riskRef = doc(collection(db, 'risks'));
        batch.set(riskRef, {
          ...risk,
          id: riskRef.id,
          uid: user.uid,
          archived: false,
          createdAt: new Date().toISOString()
        });
      });
      await batch.commit();
    } catch (error) {
      console.error("Error seeding demo risks:", error);
      setGlobalError("Failed to seed demo risks.");
    } finally {
      setIsProcessing(false);
    }
  };

  const handleSeedDemoVulnerabilities = async () => {
    if (!user) return;
    setIsProcessing(true);
    try {
      const batch = writeBatch(db);
      const now = new Date().toISOString();
      DEMO_VULNERABILITIES.forEach((vuln) => {
        const id = `${vuln.pluginId}_${vuln.host?.replace(/\./g, '_')}_${vuln.port}`;
        const vulnRef = doc(db, 'vulnerabilities', id);
        batch.set(vulnRef, {
          ...vuln,
          id,
          uid: user.uid,
          lastSeen: now
        });
      });
      await batch.commit();
    } catch (error) {
      console.error("Error seeding demo vulnerabilities:", error);
      setGlobalError("Failed to seed demo vulnerabilities.");
    } finally {
      setIsProcessing(false);
    }
  };

  const handleAddRisk = async () => {
    if (!newRisk.name || !newRisk.description || !user) return;
    const risk: Risk = {
      id: crypto.randomUUID(),
      uid: user.uid,
      name: newRisk.name!,
      description: newRisk.description!,
      likelihood: (newRisk.likelihood as any) || 'Medium',
      mitigations: newRisk.mitigations || '',
      owner: newRisk.owner || '',
      archived: false,
      createdAt: new Date().toISOString()
    };
    try {
      await setDoc(doc(db, 'risks', risk.id), risk);
      setNewRisk({ name: '', description: '', likelihood: 'Medium', mitigations: '', owner: '' });
      setIsAddingRisk(false);
    } catch (error) {
      handleFirestoreError(error, OperationType.CREATE, `risks/${risk.id}`);
    }
  };

  const handleUpdateRisk = async () => {
    if (!editingRisk || !user) return;
    try {
      await updateDoc(doc(db, 'risks', editingRisk.id), { ...editingRisk });
      setEditingRisk(null);
    } catch (error) {
      handleFirestoreError(error, OperationType.UPDATE, `risks/${editingRisk.id}`);
    }
  };

  const handleArchiveRisk = async (risk: Risk) => {
    try {
      await updateDoc(doc(db, 'risks', risk.id), { archived: !risk.archived });
    } catch (error) {
      handleFirestoreError(error, OperationType.UPDATE, `risks/${risk.id}`);
    }
  };

  const handleRemoveRisk = async (id: string) => {
    try {
      await deleteDoc(doc(db, 'risks', id));
    } catch (error) {
      handleFirestoreError(error, OperationType.DELETE, `risks/${id}`);
    }
  };

  const handleDeleteQA = async (id: string) => {
    try {
      await deleteDoc(doc(db, 'kb', id));
      setExpandedKB(prev => {
        const newState = { ...prev };
        delete newState[id];
        return newState;
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.DELETE, `kb/${id}`);
    }
  };

  const handleDeleteQuestionnaire = async (id: string) => {
    if (!window.confirm("Are you sure you want to remove this Q&A task?")) return;
    try {
      await deleteDoc(doc(db, 'questionnaires', id));
    } catch (error) {
      handleFirestoreError(error, OperationType.DELETE, `questionnaires/${id}`);
    }
  };

  const onDrop = async (acceptedFiles: File[], fileRejections: any[]) => {
    if (fileRejections.length > 0) {
      const error = fileRejections[0].errors[0];
      setGlobalError(`File rejected: ${error.message}. Please use .xlsx, .xls, or .csv files.`);
      return;
    }

    const file = acceptedFiles[0];
    if (!file) return;

    // Start UI feedback immediately
    setIsProcessing(true);
    setActiveTab('questionnaires');
    setProcessingProgress(0);
    setGlobalError(null);

    const reader = new FileReader();
    reader.onerror = () => {
      setGlobalError("Failed to read file. Please try again.");
      setIsProcessing(false);
    };

    reader.onload = async (e) => {
      try {
        const data = new Uint8Array(e.target?.result as ArrayBuffer);
        const workbook = XLSX.read(data, { type: 'array' });
        
        if (!workbook.SheetNames.length) {
          throw new Error("The Excel file appears to be empty or invalid.");
        }

        const sheetName = workbook.SheetNames[0];
        const worksheet = workbook.Sheets[sheetName];
        const json = XLSX.utils.sheet_to_json(worksheet, { header: 1 }) as any[][];
        
        if (json.length === 0) {
          throw new Error("The selected sheet is empty.");
        }
        
        // Find headers and identify columns
        const headerRow = json[0] || [];
        let questionIdx = -1;
        let answerIdx = -1;
        
        headerRow.forEach((cell, idx) => {
          const val = String(cell || '').toLowerCase();
          if (val.includes('question')) questionIdx = idx;
          if (val.includes('answer')) answerIdx = idx;
        });
        
        // Fallback if not found
        if (questionIdx === -1) questionIdx = 0;
        if (answerIdx === -1) answerIdx = 1;

        // Extract questions with original row index
        const questions = json.slice(1).map((row, idx) => ({
          text: String(row[questionIdx] || ''),
          originalRowIdx: idx + 1 // +1 because we sliced the header
        })).filter(q => q.text && q.text.trim().length > 5);
        
        if (questions.length === 0) {
          throw new Error("No questions found in the file. Ensure questions are in the first column or a column named 'Question'.");
        }

        const newQ: Questionnaire = {
          id: crypto.randomUUID(),
          uid: user?.uid || '',
          name: file.name,
          createdAt: new Date().toISOString(),
          status: 'pending',
          progress: 0,
          results: [],
          originalData: JSON.stringify(json),
          columnMapping: { questionIdx, answerIdx }
        };
        
        try {
          await setDoc(doc(db, 'questionnaires', newQ.id), newQ);
        } catch (error) {
          handleFirestoreError(error, OperationType.CREATE, `questionnaires/${newQ.id}`);
        }
        
        try {
          const results = await processQuestionnaire(questions, kb, async (progress) => {
            setProcessingProgress(progress);
            try {
              await updateDoc(doc(db, 'questionnaires', newQ.id), { progress });
            } catch (e) {
              console.error("Failed to update progress in Firestore:", e);
            }
          });

          await updateDoc(doc(db, 'questionnaires', newQ.id), { 
            status: 'completed', 
            progress: 100,
            results 
          });
        } catch (error: any) {
          console.error("Q&A processing failed:", error);
          setGlobalError(`Processing failed: ${error.message || "Unknown error"}`);
          await updateDoc(doc(db, 'questionnaires', newQ.id), { 
            status: 'completed',
            progress: 100
          });
        }
      } catch (error: any) {
        console.error("File processing error:", error);
        setGlobalError(error.message || "Failed to process the uploaded file.");
      } finally {
        setIsProcessing(false);
        setProcessingProgress(0);
      }
    };
    reader.readAsArrayBuffer(file);
  };

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ 
    onDrop,
    accept: {
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
      'application/vnd.ms-excel': ['.xls'],
      'application/vnd.ms-excel.sheet.macroEnabled.12': ['.xlsm'],
      'text/csv': ['.csv'],
      'text/plain': ['.csv']
    },
    multiple: false
  } as any);

  const handleExport = (q: Questionnaire) => {
    if (!q.results || q.results.length === 0) return;

    let workbook = XLSX.utils.book_new();
    let worksheet;

    if (q.originalData && q.columnMapping) {
      // Parse original data from string
      const data = JSON.parse(q.originalData) as any[][];
      const { answerIdx } = q.columnMapping;

      // Map results back to the original rows
      q.results.forEach(res => {
        if (res.originalRowIdx !== undefined && data[res.originalRowIdx]) {
          // Only fill if it's verified or if we want to fill everything
          // Let's fill everything but maybe add a note if it's not verified?
          // The user just said "fill", so let's fill.
          data[res.originalRowIdx][answerIdx] = res.matchedAnswer;
        }
      });

      worksheet = XLSX.utils.aoa_to_sheet(data);
      XLSX.utils.book_append_sheet(workbook, worksheet, 'Filled Q&A');
    } else {
      // Legacy export for files without original data
      const data = q.results.map((res, index) => ({
        '#': index + 1,
        'Question': res.question,
        'AI Matched Answer': res.matchedAnswer,
        'Confidence': `${Math.round(res.confidence * 100)}%`,
        'Status': res.status || 'pending',
        'Reasoning': res.reasoning || ''
      }));
      worksheet = XLSX.utils.json_to_sheet(data);
      XLSX.utils.book_append_sheet(workbook, worksheet, 'Results');
    }
    
    // Generate filename
    const filename = `CISO_Tools_Results_${q.name.replace(/\.[^/.]+$/, "")}_${new Date().toISOString().split('T')[0]}.xlsx`;
    
    XLSX.writeFile(workbook, filename);
  };

  const handleVerifyMatch = async (qId: string, resultIdx: number) => {
    const q = questionnaires.find(qn => qn.id === qId);
    if (!q || !q.results) return;
    
    const newResults = [...q.results];
    newResults[resultIdx] = { ...newResults[resultIdx], status: 'verified' };
    
    try {
      await updateDoc(doc(db, 'questionnaires', qId), { results: newResults });
    } catch (error) {
      handleFirestoreError(error, OperationType.UPDATE, `questionnaires/${qId}`);
    }
  };

  const handleRejectMatch = async (qId: string, resultIdx: number) => {
    const q = questionnaires.find(qn => qn.id === qId);
    if (!q || !q.results) return;
    
    const newResults = [...q.results];
    newResults[resultIdx] = { ...newResults[resultIdx], status: 'rejected' };
    
    try {
      await updateDoc(doc(db, 'questionnaires', qId), { results: newResults });
    } catch (error) {
      handleFirestoreError(error, OperationType.UPDATE, `questionnaires/${qId}`);
    }
  };

  const nessusFileInputRef = useRef<HTMLInputElement>(null);

  const handleNessusUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !user) return;

    setIsProcessing(true);
    setGlobalError(null);

    Papa.parse(file, {
      header: true,
      skipEmptyLines: true,
      complete: async (results) => {
        try {
          let batch = writeBatch(db);
          let count = 0;
          const now = new Date().toISOString();
          
          const scannedHosts = new Set<string>();
          const foundVulnIds = new Set<string>();

          for (const row of results.data as any[]) {
            // Nessus CSV typically has: Plugin ID, CVE, CVSS, Risk, Host, Protocol, Port, Name, Synopsis, Description, Solution, See Also
            const pluginId = row['Plugin ID'];
            const host = row['Host'];
            const severity = row['Risk']; // Critical, High, Medium, Low, None
            const name = row['Name'];
            const protocol = row['Protocol'] || 'tcp';
            const port = row['Port'] || '0';
            const description = row['Description'] || '';
            const solution = row['Solution'] || '';

            if (!host) continue;
            scannedHosts.add(host);

            if (!pluginId || severity === 'None') continue;

            // Map Nessus Risk to our severity
            let mappedSeverity: Vulnerability['severity'] = 'Info';
            if (severity === 'Critical') mappedSeverity = 'Critical';
            else if (severity === 'High') mappedSeverity = 'High';
            else if (severity === 'Medium') mappedSeverity = 'Medium';
            else if (severity === 'Low') mappedSeverity = 'Low';

            const id = `${pluginId}_${host.replace(/\./g, '_')}_${port}`;
            foundVulnIds.add(id);
            
            // Check if exists to preserve firstSeen
            const existing = vulnerabilities.find(v => v.id === id);
            
            const vuln: Vulnerability = {
              id,
              uid: user.uid,
              pluginId,
              pluginName: name.substring(0, 500),
              severity: mappedSeverity,
              host: host.substring(0, 200),
              protocol: protocol.substring(0, 50),
              port: port.substring(0, 50),
              description: description.substring(0, 10000),
              solution: solution.substring(0, 10000),
              status: 'Open',
              firstSeen: existing ? existing.firstSeen : now,
              lastSeen: now
            };

            batch.set(doc(db, 'vulnerabilities', id), vuln, { merge: true });
            count++;

            // Firestore batch limit is 500
            if (count === 490) {
              await batch.commit();
              batch = writeBatch(db);
              count = 0;
            }
          }

          // Mark vulnerabilities as remediated if they belong to a scanned host but weren't found in this scan
          for (const existingVuln of vulnerabilities) {
            if (existingVuln.status === 'Open' && scannedHosts.has(existingVuln.host) && !foundVulnIds.has(existingVuln.id)) {
              batch.update(doc(db, 'vulnerabilities', existingVuln.id), {
                status: 'Remediated',
                lastSeen: now
              });
              count++;

              if (count === 490) {
                await batch.commit();
                batch = writeBatch(db);
                count = 0;
              }
            }
          }

          if (count > 0) {
            await batch.commit();
          }
          
          setIsProcessing(false);
          if (nessusFileInputRef.current) nessusFileInputRef.current.value = '';
        } catch (error) {
          console.error("Error processing Nessus file:", error);
          setGlobalError("Failed to process Nessus file. Please ensure it's a valid CSV export.");
          setIsProcessing(false);
        }
      },
      error: (error) => {
        console.error("CSV Parse Error:", error);
        setGlobalError("Failed to parse CSV file.");
        setIsProcessing(false);
      }
    });
  };

  const handleAddPentest = async () => {
    if (!newPentest.title || !user) return;
    
    const result: PentestResult = {
      id: editingPentest?.id || crypto.randomUUID(),
      uid: user.uid,
      title: newPentest.title,
      description: newPentest.description || '',
      severity: newPentest.severity as any,
      status: newPentest.status as any,
      source: newPentest.source || 'Internal',
      date: newPentest.date || new Date().toISOString().split('T')[0],
      assignment: newPentest.assignment || '',
      remediationPlan: newPentest.remediationPlan || ''
    };

    try {
      await setDoc(doc(db, 'pentest_results', result.id), result);
      setIsAddingPentest(false);
      setEditingPentest(null);
      setNewPentest({
        title: '',
        description: '',
        severity: 'Medium',
        status: 'Open',
        source: 'Internal',
        date: new Date().toISOString().split('T')[0],
        assignment: '',
        remediationPlan: ''
      });
    } catch (error) {
      handleFirestoreError(error, editingPentest ? OperationType.UPDATE : OperationType.CREATE, `pentest_results/${result.id}`);
    }
  };

  const handleDeletePentest = async (id: string) => {
    try {
      await deleteDoc(doc(db, 'pentest_results', id));
    } catch (error) {
      handleFirestoreError(error, OperationType.DELETE, `pentest_results/${id}`);
    }
  };

  const handleUpdateCompliance = async (framework: string, controlId: string, status: ComplianceStatus) => {
    if (!user) return;
    const docId = `${framework}_${controlId}`;
    try {
      await setDoc(doc(db, 'compliance_statuses', docId), {
        uid: user.uid,
        framework,
        controlId,
        status,
        updatedAt: new Date().toISOString()
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.WRITE, `compliance_statuses/${docId}`);
    }
  };

  const filteredKb = useMemo(() => {
    if (!kbSearch) return kb;
    const search = kbSearch.toLowerCase();
    return kb.filter(item => 
      item.question.toLowerCase().includes(search) || 
      item.answer.toLowerCase().includes(search) ||
      item.category.toLowerCase().includes(search)
    );
  }, [kb, kbSearch]);

  const stats = useMemo(() => ({
    kbCount: kb.length,
    processedCount: questionnaires.filter(q => q.status === 'completed').length,
    avgConfidence: questionnaires.length > 0 
      ? Math.round(questionnaires.reduce((acc, q) => acc + (q.results?.reduce((a, r) => a + r.confidence, 0) || 0), 0) / (questionnaires.reduce((acc, q) => acc + (q.results?.length || 0), 0) || 1) * 100)
      : 0
  }), [kb, questionnaires]);

  if (!isAuthReady) {
    return (
      <div className="min-h-screen bg-bg flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin opacity-20" />
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen bg-bg flex items-center justify-center p-6">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="max-w-md w-full bg-card border border-line p-12 text-center space-y-8"
        >
          <div className="flex justify-center">
            <Shield className="w-16 h-16" />
          </div>
          <div className="space-y-2">
            <h1 className="text-3xl font-serif italic">CISO Tools</h1>
            <p className="text-sm opacity-50">Enterprise Security Q&A Automation</p>
          </div>
          <button 
            onClick={handleLogin}
            className="w-full py-4 bg-ink text-bg text-xs font-bold uppercase tracking-widest flex items-center justify-center gap-3 hover:scale-[1.02] transition-transform"
          >
            <LogIn className="w-4 h-4" />
            Sign in with Google
          </button>
          {loginError && (
            <div className="p-4 bg-red-50 border border-red-100 text-red-600 text-[10px] uppercase tracking-widest font-mono">
              Error: {loginError}
            </div>
          )}
          <p className="text-[10px] opacity-30 uppercase tracking-widest">Secure cloud storage enabled</p>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-bg text-ink font-sans selection:bg-ink selection:text-bg">
      {/* Sidebar - Tool Library */}
      <aside className={cn(
        "fixed left-0 top-0 h-full border-r border-line bg-bg z-20 transition-all duration-300",
        isSidebarOpen ? "w-64" : "w-20"
      )}>
        <div className="p-6 border-b border-line flex items-center justify-between">
          {isSidebarOpen ? (
            <button 
              onClick={() => {
                setActiveTool('questionnaire');
                setActiveTab('dashboard');
              }}
              className="flex items-center gap-3 hover:opacity-80 transition-all group"
            >
              <div className="relative">
                <div className="w-10 h-10 bg-ink text-bg rounded-lg flex items-center justify-center shadow-2xl transform group-hover:scale-105 transition-all duration-500 overflow-hidden">
                  <GlobeLock className="w-6 h-6 z-10" />
                  <div className="absolute inset-0 bg-gradient-to-tr from-transparent via-white/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-700 -translate-x-full group-hover:translate-x-full transform" />
                </div>
                <div className="absolute -top-1 -right-1 w-3 h-3 bg-emerald-500 border-2 border-bg rounded-full animate-pulse" />
              </div>
              <div className="flex flex-col">
                <div className="flex items-center gap-1">
                  <h1 className="text-xl font-black tracking-tighter leading-none font-sans">CISO</h1>
                  <div className="w-1 h-1 bg-emerald-500 rounded-full mt-1" />
                </div>
                <span className="text-[8px] uppercase tracking-[0.4em] font-mono font-bold opacity-30 mt-1">Tools Suite</span>
              </div>
            </button>
          ) : (
            <button 
              onClick={() => {
                setActiveTool('questionnaire');
                setActiveTab('dashboard');
              }}
              className="relative w-12 h-12 bg-ink text-bg rounded-lg flex items-center justify-center shadow-2xl mx-auto hover:scale-110 transition-all duration-300 group"
            >
              <GlobeLock className="w-6 h-6" />
              <div className="absolute -top-1 -right-1 w-3 h-3 bg-emerald-500 border-2 border-bg rounded-full animate-pulse" />
            </button>
          )}
          {isSidebarOpen && (
            <button 
              onClick={() => setIsSidebarOpen(!isSidebarOpen)}
              className="p-2 hover:bg-ink/5 rounded-md lg:hidden"
            >
              <Menu className="w-4 h-4" />
            </button>
          )}
        </div>
        
        <div className="p-4">
          <p className={cn(
            "text-[10px] uppercase tracking-widest opacity-30 mb-4 font-mono px-4",
            !isSidebarOpen && "text-center px-0"
          )}>
            {isSidebarOpen ? "Security Suite" : "Suite"}
          </p>
          <nav className="space-y-1">
            <button 
              onClick={() => setActiveTool('questionnaire')}
              className={cn(
                "w-full flex items-center gap-3 px-4 py-3 text-sm font-medium transition-all duration-200 rounded-lg",
                activeTool === 'questionnaire' ? "bg-ink text-bg shadow-lg" : "hover:bg-ink/5 opacity-60 hover:opacity-100"
              )}
            >
              <ClipboardList className="w-5 h-5 shrink-0" />
              {isSidebarOpen && <span>Q&A Robot</span>}
            </button>

            <button 
              onClick={() => setActiveTool('controls')}
              className={cn(
                "w-full flex items-center gap-3 px-4 py-3 text-sm font-medium transition-all duration-200 rounded-lg",
                activeTool === 'controls' ? "bg-ink text-bg shadow-lg" : "hover:bg-ink/5 opacity-60 hover:opacity-100"
              )}
            >
              <ShieldCheck className="w-5 h-5 shrink-0" />
              {isSidebarOpen && <span>Security Controls</span>}
            </button>

            <button 
              onClick={() => setActiveTool('resilience')}
              className={cn(
                "w-full flex items-center gap-3 px-4 py-3 text-sm font-medium transition-all duration-200 rounded-lg",
                activeTool === 'resilience' ? "bg-ink text-bg shadow-lg" : "hover:bg-ink/5 opacity-60 hover:opacity-100"
              )}
            >
              <Zap className="w-5 h-5 shrink-0" />
              {isSidebarOpen && <span>Resilience</span>}
            </button>

            <button 
              onClick={() => setActiveTool('scorecard')}
              className={cn(
                "w-full flex items-center gap-3 px-4 py-3 text-sm font-medium transition-all duration-200 rounded-lg",
                activeTool === 'scorecard' ? "bg-ink text-bg shadow-lg" : "hover:bg-ink/5 opacity-60 hover:opacity-100"
              )}
            >
              <BarChart3 className="w-5 h-5 shrink-0" />
              {isSidebarOpen && <span>Scorecard</span>}
            </button>
            
            <button 
              onClick={() => setActiveTool('risk')}
              className={cn(
                "w-full flex items-center gap-3 px-4 py-3 text-sm font-medium transition-all duration-200 rounded-lg",
                activeTool === 'risk' ? "bg-ink text-bg shadow-lg" : "hover:bg-ink/5 opacity-60 hover:opacity-100"
              )}
            >
              <Activity className="w-5 h-5 shrink-0" />
              {isSidebarOpen && <span>Risk Assessment</span>}
            </button>

            <button 
              onClick={() => setActiveTool('compliance')}
              className={cn(
                "w-full flex items-center gap-3 px-4 py-3 text-sm font-medium transition-all duration-200 rounded-lg",
                activeTool === 'compliance' ? "bg-ink text-bg shadow-lg" : "hover:bg-ink/5 opacity-60 hover:opacity-100"
              )}
            >
              <Lock className="w-5 h-5 shrink-0" />
              {isSidebarOpen && <span>Compliance Tracker</span>}
            </button>

            <button 
              onClick={() => setActiveTool('pentest')}
              className={cn(
                "w-full flex items-center gap-3 px-4 py-3 text-sm font-medium transition-all duration-200 rounded-lg",
                activeTool === 'pentest' ? "bg-ink text-bg shadow-lg" : "hover:bg-ink/5 opacity-60 hover:opacity-100"
              )}
            >
              <Bug className="w-5 h-5 shrink-0" />
              {isSidebarOpen && <span>Pentest Results</span>}
            </button>

            <button 
              onClick={() => setActiveTool('vulnerability')}
              className={cn(
                "w-full flex items-center gap-3 px-4 py-3 text-sm font-medium transition-all duration-200 rounded-lg",
                activeTool === 'vulnerability' ? "bg-ink text-bg shadow-lg" : "hover:bg-ink/5 opacity-60 hover:opacity-100"
              )}
            >
              <Radar className="w-5 h-5 shrink-0" />
              {isSidebarOpen && <span>Vulnerability Mgmt</span>}
            </button>
          </nav>
        </div>
        
        <div className="absolute bottom-6 left-4 right-4 space-y-4">
          <button 
            onClick={() => setActiveTool('settings')}
            className={cn(
              "w-full flex items-center gap-3 px-4 py-3 text-sm font-medium transition-all duration-200 rounded-lg",
              activeTool === 'settings' ? "bg-ink text-bg shadow-lg" : "hover:bg-ink/5 opacity-60 hover:opacity-100"
            )}
          >
            <Settings className="w-5 h-5 shrink-0" />
            {isSidebarOpen && <span>Settings</span>}
          </button>

          <div className={cn(
            "p-4 border border-line bg-card/50 backdrop-blur-sm rounded-xl transition-all duration-300",
            !isSidebarOpen && "p-2"
          )}>
            {isSidebarOpen ? (
              <>
                <p className="text-[10px] uppercase tracking-widest opacity-50 mb-2">System Status</p>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                  <span className="text-xs font-mono uppercase">AI Engine Ready</span>
                </div>
              </>
            ) : (
              <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse mx-auto" />
            )}
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className={cn(
        "min-h-screen transition-all duration-300",
        isSidebarOpen ? "pl-64" : "pl-20"
      )}>
        <header className="h-20 border-b border-line flex items-center justify-between px-12 sticky top-0 bg-bg/80 backdrop-blur-md z-10">
          <div className="flex items-center gap-8">
            <div className="flex items-center gap-3">
              {toolIcons[activeTool]}
              <span className="text-xs font-mono uppercase tracking-widest font-bold">{toolNames[activeTool]}</span>
            </div>
            
            {activeTool === 'questionnaire' && (
              <>
                <div className="h-8 w-[1px] bg-line" />
                <nav className="flex items-center gap-1">
                  <button 
                    onClick={() => setActiveTab('dashboard')}
                    className={cn(
                      "px-4 py-2 text-[10px] font-bold uppercase tracking-widest transition-all rounded-md",
                      activeTab === 'dashboard' ? "bg-ink text-bg" : "hover:bg-ink/5 opacity-50"
                    )}
                  >
                    Dashboard
                  </button>
                  <button 
                    onClick={() => setActiveTab('kb')}
                    className={cn(
                      "px-4 py-2 text-[10px] font-bold uppercase tracking-widest transition-all rounded-md",
                      activeTab === 'kb' ? "bg-ink text-bg" : "hover:bg-ink/5 opacity-50"
                    )}
                  >
                    Knowledge Base
                  </button>
                  <button 
                    onClick={() => setActiveTab('questionnaires')}
                    className={cn(
                      "px-4 py-2 text-[10px] font-bold uppercase tracking-widest transition-all rounded-md",
                      activeTab === 'questionnaires' ? "bg-ink text-bg" : "hover:bg-ink/5 opacity-50"
                    )}
                  >
                    Q&A
                  </button>
                </nav>
              </>
            )}
          </div>
          
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2 text-[10px] uppercase tracking-widest opacity-50">
                <span className="w-2 h-2 rounded-full bg-blue-500" />
                v1.0.4 Enterprise
              </div>
              <button 
                onClick={handleLogout}
                className="flex items-center gap-3 hover:opacity-50 transition-opacity"
              >
                <div className="w-10 h-10 rounded-full border border-line flex items-center justify-center bg-card overflow-hidden">
                  {user.photoURL ? (
                    <img src={user.photoURL} alt={user.displayName || ''} className="w-full h-full object-cover" />
                  ) : (
                    <span className="text-xs font-bold">{user.displayName?.split(' ').map(n => n[0]).join('') || 'U'}</span>
                  )}
                </div>
                <LogOut className="w-4 h-4 opacity-30" />
              </button>
            </div>
        </header>

        <div className="p-12 max-w-7xl mx-auto">
          {globalError && (
            <motion.div 
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              className="mb-8 p-4 bg-red-500/10 border border-red-500/50 text-red-500 text-xs font-bold uppercase tracking-widest flex items-center justify-between"
            >
              <div className="flex items-center gap-3">
                <AlertCircle className="w-4 h-4" />
                {globalError}
              </div>
              <button onClick={() => setGlobalError(null)}>
                <X className="w-4 h-4" />
              </button>
            </motion.div>
          )}

          <AnimatePresence mode="wait">
            {activeTool === 'questionnaire' && (
              <motion.div
                key="questionnaire-tool"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
              >
                <AnimatePresence mode="wait">
                  {activeTab === 'dashboard' && (
                    <motion.div 
                      key="dashboard"
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -20 }}
                      className="space-y-12"
                    >
                      <div className="grid grid-cols-3 gap-8">
                        <div className="p-8 border border-line bg-card group hover:bg-ink hover:text-bg transition-all duration-300">
                          <p className="text-[10px] uppercase tracking-widest opacity-50 mb-4 font-mono">KB Entries</p>
                          <h3 className="text-6xl font-serif italic">{stats.kbCount}</h3>
                          <p className="mt-4 text-sm opacity-70">Verified security responses</p>
                        </div>
                        <div className="p-8 border border-line bg-card group hover:bg-ink hover:text-bg transition-all duration-300">
                          <p className="text-[10px] uppercase tracking-widest opacity-50 mb-4 font-mono">Processed</p>
                          <h3 className="text-6xl font-serif italic">{stats.processedCount}</h3>
                          <p className="mt-4 text-sm opacity-70">Q&A Tasks completed</p>
                        </div>
                        <div className="p-8 border border-line bg-card group hover:bg-ink hover:text-bg transition-all duration-300">
                          <p className="text-[10px] uppercase tracking-widest opacity-50 mb-4 font-mono">AI Confidence</p>
                          <h3 className="text-6xl font-serif italic">{stats.avgConfidence}%</h3>
                          <p className="mt-4 text-sm opacity-70">Average match accuracy</p>
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-12">
                        <div className="space-y-6">
                          <h2 className="text-2xl font-serif italic">Quick Actions</h2>
                          <div className="grid grid-cols-1 gap-4">
                            <div 
                              {...getRootProps()} 
                              className={cn(
                                "p-12 border-2 border-dashed border-line flex flex-col items-center justify-center gap-4 cursor-pointer transition-all duration-200",
                                isDragActive ? "bg-ink/10 scale-[0.99]" : "hover:bg-ink/5"
                              )}
                            >
                              <input {...getInputProps()} />
                              <Upload className="w-12 h-12 opacity-20" />
                              <div className="text-center">
                                <p className="font-bold uppercase tracking-widest text-sm">Upload Q&A File</p>
                                <p className="text-xs opacity-50 mt-1">Excel, CSV, or Word files</p>
                              </div>
                            </div>
                          </div>
                        </div>

                        <div className="space-y-6">
                          <h2 className="text-2xl font-serif italic">Recent Activity</h2>
                          <div className="border border-line bg-card divide-y divide-line">
                            {questionnaires.slice(0, 5).map((q) => (
                              <div key={q.id} className="p-4 flex items-center justify-between hover:bg-ink/5 transition-colors">
                                <div className="flex items-center gap-4">
                                  <div className={cn(
                                    "w-2 h-2 rounded-full",
                                    q.status === 'completed' ? "bg-emerald-500" : "bg-amber-500 animate-pulse"
                                  )} />
                                  <div>
                                    <p className="text-sm font-bold uppercase tracking-tight">{q.name}</p>
                                    <p className="text-[10px] opacity-50 font-mono">{new Date(q.createdAt).toLocaleDateString()}</p>
                                  </div>
                                </div>
                                <ChevronRight className="w-4 h-4 opacity-20" />
                              </div>
                            ))}
                            {questionnaires.length === 0 && (
                              <div className="p-12 text-center opacity-30 italic text-sm">No recent activity</div>
                            )}
                          </div>
                        </div>
                      </div>
                    </motion.div>
                  )}

                  {activeTab === 'kb' && (
                    <motion.div 
                      key="kb"
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -20 }}
                      className="space-y-8"
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <h2 className="text-3xl font-serif italic">Knowledge Base</h2>
                          <p className="text-xs opacity-50 mt-1">Import security policies, previous Q&A tasks, or compliance docs.</p>
                        </div>
                        <div className="flex gap-4">
                          <input 
                            type="file" 
                            ref={kbFileInputRef} 
                            onChange={handleKBFileChange} 
                            className="hidden" 
                            accept=".xlsx,.xls,.csv,.docx,.pdf"
                          />
                          <button 
                            onClick={() => kbFileInputRef.current?.click()}
                            className="px-6 py-3 border border-line text-xs font-bold uppercase tracking-widest hover:bg-ink hover:text-bg transition-all flex items-center gap-2"
                          >
                            <Upload className="w-4 h-4" />
                            Import
                          </button>
                          <button 
                            onClick={() => {
                              const sampleData: QAItem[] = [
                                { id: '1', uid: user.uid, question: 'Do you encrypt data at rest?', answer: 'Yes, all data at rest is encrypted using AES-256 encryption. Keys are managed via AWS KMS with strict rotation policies.', category: 'Encryption', lastUpdated: new Date().toISOString() },
                                { id: '2', uid: user.uid, question: 'What is your password policy?', answer: 'Our password policy requires a minimum of 12 characters, including uppercase, lowercase, numbers, and special characters. MFA is mandatory for all employees.', category: 'Access Control', lastUpdated: new Date().toISOString() },
                                { id: '3', uid: user.uid, question: 'Are you SOC2 Type II compliant?', answer: 'Yes, we undergo annual SOC2 Type II audits. Our latest report is available upon request under NDA.', category: 'Compliance', lastUpdated: new Date().toISOString() },
                                { id: '4', uid: user.uid, question: 'How do you handle data breaches?', answer: 'We have a formal Incident Response Plan. In the event of a breach, customers are notified within 24 hours of confirmation.', category: 'General', lastUpdated: new Date().toISOString() },
                              ];
                              // Batch upload to Firestore
                              sampleData.forEach(async (item) => {
                                try {
                                  await setDoc(doc(db, 'kb', item.id), item);
                                } catch (error) {
                                  handleFirestoreError(error, OperationType.CREATE, `kb/${item.id}`);
                                }
                              });
                            }}
                            className="px-6 py-3 border border-line text-xs font-bold uppercase tracking-widest hover:bg-ink hover:text-bg transition-all"
                          >
                            Load Sample Data
                          </button>
                          <button 
                            onClick={() => setIsAddingQA(true)}
                            className="px-6 py-3 bg-ink text-bg text-xs font-bold uppercase tracking-widest flex items-center gap-2 hover:scale-105 transition-transform"
                          >
                            <Plus className="w-4 h-4" />
                            Add Entry
                          </button>
                        </div>
                      </div>

                      <div className="relative">
                        <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 opacity-30" />
                        <input 
                          type="text" 
                          placeholder="Search knowledge base..."
                          value={kbSearch}
                          onChange={(e) => setKbSearch(e.target.value)}
                          className="w-full pl-12 pr-4 py-4 bg-card border border-line text-sm focus:outline-none focus:ring-2 focus:ring-ink/10"
                        />
                      </div>

                      <div className="border border-line bg-card overflow-hidden">
                        <div className="grid grid-cols-[1fr,2fr,1fr,100px] gap-4 p-4 border-b border-line bg-ink/5 text-[10px] font-mono uppercase tracking-widest">
                          <div>Question</div>
                          <div>Answer</div>
                          <div>Category</div>
                          <div className="text-right">Actions</div>
                        </div>
                        <div className="divide-y divide-line">
                          {filteredKb.map((item) => (
                            <div key={item.id} className="grid grid-cols-[1fr,2fr,1fr,100px] gap-4 p-6 items-start hover:bg-ink/5 transition-colors group">
                              <div className="text-sm font-bold leading-tight">{item.question}</div>
                              <div className="space-y-2">
                                <div className={cn(
                                  "text-sm opacity-70 leading-relaxed",
                                  !expandedKB[item.id] && "line-clamp-3"
                                )}>
                                  {item.answer}
                                </div>
                                {item.answer.length > 200 && (
                                  <button 
                                    onClick={() => setExpandedKB(prev => ({ ...prev, [item.id]: !prev[item.id] }))}
                                    className="text-[10px] font-bold uppercase tracking-widest opacity-50 hover:opacity-100"
                                  >
                                    {expandedKB[item.id] ? 'Show Less' : 'Read More'}
                                  </button>
                                )}
                              </div>
                              <div>
                                <span className="px-2 py-1 border border-line text-[10px] uppercase tracking-widest font-mono">
                                  {item.category}
                                </span>
                              </div>
                              <div className="flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                <button className="p-2 hover:bg-ink hover:text-bg transition-colors">
                                  <Edit2 className="w-3 h-3" />
                                </button>
                                <button 
                                  onClick={() => handleDeleteQA(item.id)}
                                  className="p-2 hover:bg-red-500 hover:text-white transition-colors"
                                >
                                  <Trash2 className="w-3 h-3" />
                                </button>
                              </div>
                            </div>
                          ))}
                          {filteredKb.length === 0 && (
                            <div className="p-24 text-center">
                              <Database className="w-12 h-12 opacity-10 mx-auto mb-4" />
                              <p className="text-sm opacity-30 italic">
                                {kbSearch ? 'No matching entries found.' : 'Knowledge base is empty. Add your first entry or import a document to start automating.'}
                              </p>
                            </div>
                          )}
                        </div>
                      </div>
                    </motion.div>
                  )}

                  {activeTab === 'questionnaires' && (
                    <motion.div 
                      key="questionnaires"
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -20 }}
                      className="space-y-8"
                    >
                      <div className="flex items-center justify-between">
                        <h2 className="text-3xl font-serif italic">Q&A Tasks</h2>
                        <div 
                          {...getRootProps()} 
                          className="px-6 py-3 bg-ink text-bg text-xs font-bold uppercase tracking-widest flex items-center gap-2 hover:scale-105 transition-transform cursor-pointer"
                        >
                          <input {...getInputProps()} />
                          <Upload className="w-4 h-4" />
                          New Scan
                        </div>
                      </div>

                      {isProcessing && (
                        <div className="p-8 border border-line bg-card space-y-4">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-3">
                              <Loader2 className="w-5 h-5 animate-spin" />
                              <span className="text-sm font-bold uppercase tracking-widest">AI Matching in progress...</span>
                            </div>
                            <span className="text-xs font-mono">{processingProgress}%</span>
                          </div>
                          <div className="h-2 bg-ink/10 w-full overflow-hidden">
                            <motion.div 
                              className="h-full bg-ink"
                              initial={{ width: 0 }}
                              animate={{ width: `${processingProgress}%` }}
                            />
                          </div>
                          <p className="text-[10px] opacity-50 uppercase tracking-widest">Comparing incoming questions against security database</p>
                        </div>
                      )}

                      <div className="space-y-6">
                        {questionnaires.map((q) => (
                          <div key={q.id} className="border border-line bg-card overflow-hidden">
                            <div className="p-6 border-b border-line flex items-center justify-between bg-ink/5">
                              <div className="flex items-center gap-4">
                                <FileText className="w-6 h-6 opacity-30" />
                                <div>
                                  <h3 className="font-bold uppercase tracking-tight">{q.name}</h3>
                                  <p className="text-[10px] opacity-50 font-mono">
                                    {new Date(q.createdAt).toLocaleString()} • {q.results?.length || 0} Questions
                                  </p>
                                </div>
                              </div>
                              <div className="flex items-center gap-4">
                                {q.status === 'completed' && (
                                  <button 
                                    onClick={() => handleExport(q)}
                                    className="px-4 py-2 border border-line text-[10px] font-bold uppercase tracking-widest hover:bg-ink hover:text-bg transition-all flex items-center gap-2"
                                  >
                                    <Download className="w-3 h-3" />
                                    Export Results
                                  </button>
                                )}
                                <div className={cn(
                                  "px-3 py-1 text-[10px] font-bold uppercase tracking-widest border",
                                  q.status === 'completed' ? "bg-emerald-50 border-emerald-500 text-emerald-700" : "bg-amber-50 border-amber-500 text-amber-700 animate-pulse"
                                )}>
                                  {q.status}
                                </div>
                                <button 
                                  onClick={() => handleDeleteQuestionnaire(q.id)}
                                  className="p-2 border border-line text-ink hover:bg-red-500 hover:text-white hover:border-red-500 transition-all"
                                  title="Delete Q&A Task"
                                >
                                  <Trash2 className="w-3 h-3" />
                                </button>
                              </div>
                            </div>
                            
                            {q.status === 'completed' && q.results && (
                              <div className="divide-y divide-line">
                                {q.results.map((res, idx) => (
                                  <div key={idx} className="p-6 grid grid-cols-[1fr,1fr,150px] gap-8 items-start hover:bg-ink/5 transition-colors">
                                    <div className="space-y-2">
                                      <p className="text-[10px] font-mono uppercase opacity-40">Question {idx + 1}</p>
                                      <p className="text-sm font-bold leading-tight">{res.question}</p>
                                    </div>
                                    <div className="space-y-2">
                                      <p className="text-[10px] font-mono uppercase opacity-40">AI Matched Answer</p>
                                      <p className="text-sm opacity-70 leading-relaxed">{res.matchedAnswer}</p>
                                    </div>
                                    <div className="flex flex-col items-end gap-3">
                                      <div className="text-right">
                                        <p className="text-[10px] font-mono uppercase opacity-40 mb-1">Confidence</p>
                                        <div className={cn(
                                          "text-lg font-serif italic flex items-center gap-2",
                                          res.status === 'verified' ? "text-emerald-600" : res.status === 'rejected' ? "text-red-600" : res.confidence > 0.8 ? "text-emerald-600" : res.confidence > 0.5 ? "text-amber-600" : "text-red-600"
                                        )}>
                                          {Math.round(res.confidence * 100)}%
                                          {res.status === 'verified' && <CheckCircle2 className="w-4 h-4" />}
                                          {res.status === 'rejected' && <AlertCircle className="w-4 h-4" />}
                                        </div>
                                      </div>
                                      <div className="flex gap-1">
                                        <button 
                                          onClick={() => handleVerifyMatch(q.id, idx)}
                                          className={cn(
                                            "p-2 border border-line transition-colors",
                                            res.status === 'verified' ? "bg-emerald-500 text-white" : "hover:bg-emerald-500 hover:text-white"
                                          )}
                                        >
                                          <Check className="w-3 h-3" />
                                        </button>
                                        <button 
                                          onClick={() => handleRejectMatch(q.id, idx)}
                                          className={cn(
                                            "p-2 border border-line transition-colors",
                                            res.status === 'rejected' ? "bg-red-500 text-white" : "hover:bg-red-500 hover:text-white"
                                          )}
                                        >
                                          <X className="w-3 h-3" />
                                        </button>
                                      </div>
                                      {res.status === 'verified' && res.matchedAnswer.startsWith('[AI Suggestion]') && (
                                        <button 
                                          onClick={async () => {
                                            const item: QAItem = {
                                              id: crypto.randomUUID(),
                                              uid: user.uid,
                                              question: res.question,
                                              answer: res.matchedAnswer.replace('[AI Suggestion] ', ''),
                                              category: 'General',
                                              lastUpdated: new Date().toISOString()
                                            };
                                            try {
                                              await setDoc(doc(db, 'kb', item.id), item);
                                              // Update result to remove suggestion prefix
                                              const newResults = [...q.results!];
                                              newResults[idx] = { ...newResults[idx], matchedAnswer: item.answer };
                                              await updateDoc(doc(db, 'questionnaires', q.id), { results: newResults });
                                            } catch (error) {
                                              handleFirestoreError(error, OperationType.WRITE, `kb/${item.id}`);
                                            }
                                          }}
                                          className="mt-2 text-[10px] font-bold uppercase tracking-widest text-blue-600 hover:underline"
                                        >
                                          + Add to KB
                                        </button>
                                      )}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        ))}
                        {questionnaires.length === 0 && !isProcessing && (
                          <div className="p-24 border border-dashed border-line text-center">
                            <FileText className="w-12 h-12 opacity-10 mx-auto mb-4" />
                            <p className="text-sm opacity-30 italic">No Q&A tasks scanned yet. Upload an Excel file to begin.</p>
                          </div>
                        )}
                      </div>
                    </motion.div>
                  )}

                </AnimatePresence>
              </motion.div>
            )}

            {activeTool === 'settings' && (
              <motion.div 
                key="settings-tool"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-8 max-w-2xl"
              >
                <div className="flex items-center justify-between">
                  <h2 className="text-3xl font-serif italic">Settings</h2>
                </div>

                <div className="space-y-6">
                  <div className="p-8 border border-line bg-card space-y-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-bold uppercase tracking-tight">Appearance</h3>
                        <p className="text-xs opacity-50">Choose between light and dark interface</p>
                      </div>
                      <div className="flex p-1 bg-bg border border-line rounded-lg">
                        <button 
                          onClick={() => setTheme('light')}
                          className={cn(
                            "flex items-center gap-2 px-4 py-2 text-[10px] font-bold uppercase tracking-widest transition-all",
                            theme === 'light' ? "bg-ink text-bg shadow-sm" : "hover:opacity-50"
                          )}
                        >
                          <Sun className="w-3 h-3" />
                          Light
                        </button>
                        <button 
                          onClick={() => setTheme('dark')}
                          className={cn(
                            "flex items-center gap-2 px-4 py-2 text-[10px] font-bold uppercase tracking-widest transition-all",
                            theme === 'dark' ? "bg-ink text-bg shadow-sm" : "hover:opacity-50"
                          )}
                        >
                          <Moon className="w-3 h-3" />
                          Dark
                        </button>
                      </div>
                    </div>

                    <div className="h-px bg-line opacity-10" />

                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-bold uppercase tracking-tight">Account</h3>
                        <p className="text-xs opacity-50">Logged in as {user?.email}</p>
                      </div>
                      <button 
                        onClick={handleLogout}
                        className="px-4 py-2 border border-line text-[10px] font-bold uppercase tracking-widest hover:bg-red-500 hover:text-white hover:border-red-500 transition-all flex items-center gap-2"
                      >
                        <LogOut className="w-3 h-3" />
                        Sign Out
                      </button>
                    </div>
                  </div>

                  <div className="p-8 border border-line bg-card space-y-4">
                    <h3 className="font-bold uppercase tracking-tight">System Information</h3>
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-1">
                        <p className="text-[10px] opacity-50 uppercase tracking-widest">Version</p>
                        <p className="text-xs font-mono">v1.0.4 Enterprise</p>
                      </div>
                      <div className="space-y-1">
                        <p className="text-[10px] opacity-50 uppercase tracking-widest">Environment</p>
                        <p className="text-xs font-mono">Production</p>
                      </div>
                      <div className="space-y-1">
                        <p className="text-[10px] opacity-50 uppercase tracking-widest">User ID</p>
                        <p className="text-[10px] font-mono opacity-30 truncate">{user?.uid}</p>
                      </div>
                    </div>
                  </div>

                  <div className="p-8 border border-line bg-card space-y-6">
                    <div className="space-y-1">
                      <h3 className="font-bold uppercase tracking-tight">Resilience Integrations</h3>
                      <p className="text-xs opacity-50">Configure API credentials for your enterprise tools. These are stored locally in your browser.</p>
                    </div>

                    <div className="space-y-6">
                      {/* Veeam Settings */}
                      <div className="space-y-4">
                        <h4 className="text-sm font-medium flex items-center gap-2">
                          <Server className="w-4 h-4 opacity-50" />
                          Veeam Enterprise Manager
                        </h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="space-y-1.5">
                            <label className="text-[10px] font-bold uppercase tracking-widest opacity-50">API URL</label>
                            <input
                              type="text"
                              value={veeamUrl}
                              onChange={(e) => setVeeamUrl(e.target.value)}
                              placeholder="https://veeam.company.local:9398"
                              className="w-full px-3 py-2 bg-transparent border border-line rounded-lg text-sm focus:outline-none focus:border-ink transition-colors"
                            />
                          </div>
                          <div className="space-y-1.5">
                            <label className="text-[10px] font-bold uppercase tracking-widest opacity-50">API Token</label>
                            <input
                              type="password"
                              value={veeamToken}
                              onChange={(e) => setVeeamToken(e.target.value)}
                              placeholder="••••••••••••••••"
                              className="w-full px-3 py-2 bg-transparent border border-line rounded-lg text-sm focus:outline-none focus:border-ink transition-colors"
                            />
                          </div>
                        </div>
                      </div>

                      <div className="h-px bg-line opacity-10" />

                      {/* Microsoft Graph Settings */}
                      <div className="space-y-4">
                        <h4 className="text-sm font-medium flex items-center gap-2">
                          <Cloud className="w-4 h-4 opacity-50" />
                          Microsoft 365 (OneDrive)
                        </h4>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                          <div className="space-y-1.5">
                            <label className="text-[10px] font-bold uppercase tracking-widest opacity-50">Tenant ID</label>
                            <input
                              type="text"
                              value={msTenantId}
                              onChange={(e) => setMsTenantId(e.target.value)}
                              placeholder="00000000-0000-0000-0000-000000000000"
                              className="w-full px-3 py-2 bg-transparent border border-line rounded-lg text-sm focus:outline-none focus:border-ink transition-colors"
                            />
                          </div>
                          <div className="space-y-1.5">
                            <label className="text-[10px] font-bold uppercase tracking-widest opacity-50">Client ID</label>
                            <input
                              type="text"
                              value={msClientId}
                              onChange={(e) => setMsClientId(e.target.value)}
                              placeholder="00000000-0000-0000-0000-000000000000"
                              className="w-full px-3 py-2 bg-transparent border border-line rounded-lg text-sm focus:outline-none focus:border-ink transition-colors"
                            />
                          </div>
                          <div className="space-y-1.5">
                            <label className="text-[10px] font-bold uppercase tracking-widest opacity-50">Client Secret</label>
                            <input
                              type="password"
                              value={msClientSecret}
                              onChange={(e) => setMsClientSecret(e.target.value)}
                              placeholder="••••••••••••••••"
                              className="w-full px-3 py-2 bg-transparent border border-line rounded-lg text-sm focus:outline-none focus:border-ink transition-colors"
                            />
                          </div>
                        </div>
                      </div>

                      <div className="h-px bg-line opacity-10" />

                      {/* Zerto Settings */}
                      <div className="space-y-4">
                        <h4 className="text-sm font-medium flex items-center gap-2">
                          <ArrowRightLeft className="w-4 h-4 opacity-50" />
                          Zerto REST API
                        </h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="space-y-1.5">
                            <label className="text-[10px] font-bold uppercase tracking-widest opacity-50">API URL</label>
                            <input
                              type="text"
                              value={zertoUrl}
                              onChange={(e) => setZertoUrl(e.target.value)}
                              placeholder="https://zvm.company.local:9669"
                              className="w-full px-3 py-2 bg-transparent border border-line rounded-lg text-sm focus:outline-none focus:border-ink transition-colors"
                            />
                          </div>
                          <div className="space-y-1.5">
                            <label className="text-[10px] font-bold uppercase tracking-widest opacity-50">API Token</label>
                            <input
                              type="password"
                              value={zertoToken}
                              onChange={(e) => setZertoToken(e.target.value)}
                              placeholder="••••••••••••••••"
                              className="w-full px-3 py-2 bg-transparent border border-line rounded-lg text-sm focus:outline-none focus:border-ink transition-colors"
                            />
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}

            {activeTool === 'controls' && (
              <motion.div
                key="controls-tool"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-8"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-3xl font-serif italic">Security Controls</h2>
                    <p className="text-sm opacity-50 mt-1">Oversee active security tools and their current status.</p>
                  </div>
                  <button 
                    onClick={() => {
                      setControlsLoading(true);
                      setTimeout(() => setControlsLoading(false), 800);
                    }}
                    className="flex items-center gap-2 px-4 py-2 border border-line text-[10px] font-bold uppercase tracking-widest hover:bg-ink hover:text-bg transition-colors"
                  >
                    <Activity className={cn("w-3 h-3", controlsLoading && "animate-spin")} />
                    Refresh
                  </button>
                </div>

                {controlsLoading ? (
                  <div className="flex flex-col items-center justify-center min-h-[40vh] space-y-4">
                    <Loader2 className="w-8 h-8 animate-spin opacity-50" />
                    <p className="text-sm opacity-50">Fetching security controls telemetry...</p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {/* XDR Card */}
                    <div className="p-6 border border-line bg-card space-y-6 flex flex-col">
                      <div className="flex items-start justify-between">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <Crosshair className="w-5 h-5 text-red-500" />
                            <h3 className="font-bold uppercase tracking-tight">XDR</h3>
                          </div>
                          <p className="text-xs opacity-50">Extended Detection & Response</p>
                        </div>
                        <span className={cn(
                          "px-2 py-1 text-[10px] font-bold uppercase tracking-widest rounded-full",
                          xdrData?.status === 'Operational' ? "bg-green-500/10 text-green-600" : "bg-red-500/10 text-red-600"
                        )}>
                          {xdrData?.status || 'Unknown'}
                        </span>
                      </div>
                      
                      <div className="grid grid-cols-2 gap-4 flex-1">
                        <div className="space-y-1">
                          <p className="text-[10px] uppercase tracking-widest opacity-50">Active Threats</p>
                          <p className="text-2xl font-light text-red-500">{xdrData?.activeThreats || 0}</p>
                        </div>
                        <div className="space-y-1">
                          <p className="text-[10px] uppercase tracking-widest opacity-50">Monitored</p>
                          <p className="text-2xl font-light">{xdrData?.endpointsMonitored || 0}</p>
                        </div>
                        <div className="space-y-1">
                          <p className="text-[10px] uppercase tracking-widest opacity-50">Isolated</p>
                          <p className="text-2xl font-light text-orange-500">{xdrData?.isolatedDevices || 0}</p>
                        </div>
                        <div className="space-y-1">
                          <p className="text-[10px] uppercase tracking-widest opacity-50">Last Scan</p>
                          <p className="text-sm font-mono mt-1">{xdrData?.lastScan || 'N/A'}</p>
                        </div>
                      </div>
                    </div>

                    {/* DLP Card */}
                    <div className="p-6 border border-line bg-card space-y-6 flex flex-col">
                      <div className="flex items-start justify-between">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <EyeOff className="w-5 h-5 text-blue-500" />
                            <h3 className="font-bold uppercase tracking-tight">DLP</h3>
                          </div>
                          <p className="text-xs opacity-50">Data Loss Prevention</p>
                        </div>
                        <span className={cn(
                          "px-2 py-1 text-[10px] font-bold uppercase tracking-widest rounded-full",
                          dlpData?.status === 'Operational' ? "bg-green-500/10 text-green-600" : "bg-red-500/10 text-red-600"
                        )}>
                          {dlpData?.status || 'Unknown'}
                        </span>
                      </div>
                      
                      <div className="grid grid-cols-2 gap-4 flex-1">
                        <div className="space-y-1">
                          <p className="text-[10px] uppercase tracking-widest opacity-50">Incidents Today</p>
                          <p className="text-2xl font-light text-orange-500">{dlpData?.incidentsToday || 0}</p>
                        </div>
                        <div className="space-y-1">
                          <p className="text-[10px] uppercase tracking-widest opacity-50">Blocked</p>
                          <p className="text-2xl font-light text-green-500">{dlpData?.blockedTransfers || 0}</p>
                        </div>
                        <div className="space-y-1 col-span-2">
                          <p className="text-[10px] uppercase tracking-widest opacity-50">Active Policies</p>
                          <p className="text-2xl font-light">{dlpData?.activePolicies || 0}</p>
                        </div>
                      </div>
                    </div>

                    {/* BitLocker Card */}
                    <div className="p-6 border border-line bg-card space-y-6 flex flex-col">
                      <div className="flex items-start justify-between">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <Key className="w-5 h-5 text-yellow-500" />
                            <h3 className="font-bold uppercase tracking-tight">BitLocker</h3>
                          </div>
                          <p className="text-xs opacity-50">Disk Encryption</p>
                        </div>
                        <span className={cn(
                          "px-2 py-1 text-[10px] font-bold uppercase tracking-widest rounded-full",
                          bitlockerData?.status === 'Operational' ? "bg-green-500/10 text-green-600" : 
                          bitlockerData?.status === 'Warning' ? "bg-yellow-500/10 text-yellow-600" : "bg-red-500/10 text-red-600"
                        )}>
                          {bitlockerData?.status || 'Unknown'}
                        </span>
                      </div>
                      
                      <div className="grid grid-cols-2 gap-4 flex-1">
                        <div className="space-y-1">
                          <p className="text-[10px] uppercase tracking-widest opacity-50">Compliant</p>
                          <p className="text-2xl font-light text-green-500">{bitlockerData?.compliantDevices || 0}</p>
                        </div>
                        <div className="space-y-1">
                          <p className="text-[10px] uppercase tracking-widest opacity-50">Non-Compliant</p>
                          <p className="text-2xl font-light text-red-500">{bitlockerData?.nonCompliantDevices || 0}</p>
                        </div>
                        <div className="space-y-1 col-span-2">
                          <p className="text-[10px] uppercase tracking-widest opacity-50">Encryption Rate</p>
                          <div className="flex items-center gap-3 mt-1">
                            <div className="flex-1 h-2 bg-line/20 rounded-full overflow-hidden">
                              <div 
                                className={cn(
                                  "h-full rounded-full",
                                  (bitlockerData?.encryptionRate || 0) > 95 ? "bg-green-500" : "bg-yellow-500"
                                )}
                                style={{ width: `${bitlockerData?.encryptionRate || 0}%` }}
                              />
                            </div>
                            <span className="text-sm font-mono">{bitlockerData?.encryptionRate || 0}%</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </motion.div>
            )}

            {activeTool === 'risk' && (
              <motion.div
                key="risk-tool"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-8"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-3xl font-serif italic">Risk Assessment</h2>
                    <p className="text-sm opacity-50">Manage and mitigate organizational security risks.</p>
                  </div>
                  <div className="flex items-center gap-4">
                    {risks.length === 0 && (
                      <button 
                        onClick={handleSeedDemoRisks}
                        className="flex items-center gap-2 px-6 py-3 border border-ink/20 text-[10px] font-bold uppercase tracking-widest hover:bg-ink/5 transition-colors"
                      >
                        <Zap className="w-4 h-4 text-amber-500" />
                        Seed Demo Risks
                      </button>
                    )}
                    <button 
                      onClick={() => setIsAddingRisk(true)}
                      className="flex items-center gap-2 px-6 py-3 bg-ink text-bg text-[10px] font-bold uppercase tracking-widest hover:scale-105 transition-transform"
                    >
                      <Plus className="w-4 h-4" />
                      Add Risk
                    </button>
                  </div>
                </div>

                <div className="border border-line bg-card overflow-hidden">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-line bg-bg/50">
                        <th className="p-4 text-[10px] font-mono uppercase tracking-widest opacity-50">ID</th>
                        <th className="p-4 text-[10px] font-mono uppercase tracking-widest opacity-50">Risk Name</th>
                        <th className="p-4 text-[10px] font-mono uppercase tracking-widest opacity-50">Risk Description</th>
                        <th className="p-4 text-[10px] font-mono uppercase tracking-widest opacity-50">Likelihood</th>
                        <th className="p-4 text-[10px] font-mono uppercase tracking-widest opacity-50">Owner</th>
                        <th className="p-4 text-[10px] font-mono uppercase tracking-widest opacity-50 text-right">Risk Mitigation</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line">
                      {risks.filter(r => !r.archived).map((risk, idx) => (
                        <tr key={risk.id} className="hover:bg-ink/[0.02] transition-colors group">
                          <td className="p-4 text-[10px] font-mono opacity-30">R-{idx + 1}</td>
                          <td className="p-4 font-bold text-sm">{risk.name}</td>
                          <td className="p-4 text-xs opacity-50 max-w-xs truncate">{risk.description}</td>
                          <td className="p-4">
                            <span className={cn(
                              "px-2 py-1 text-[8px] font-bold uppercase tracking-widest rounded-full",
                              risk.likelihood === 'Low' && "bg-emerald-100 text-emerald-700",
                              risk.likelihood === 'Medium' && "bg-amber-100 text-amber-700",
                              risk.likelihood === 'High' && "bg-orange-100 text-orange-700",
                              risk.likelihood === 'Critical' && "bg-red-100 text-red-700"
                            )}>
                              {risk.likelihood}
                            </span>
                          </td>
                          <td className="p-4 text-xs">{risk.owner}</td>
                          <td className="p-4 text-right">
                            <div className="flex items-center justify-end gap-4">
                              <div className="text-xs opacity-50 line-clamp-1 max-w-[200px] text-left">{risk.mitigations}</div>
                              <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                                <button 
                                  onClick={() => setEditingRisk(risk)}
                                  className="p-2 hover:bg-ink/5 rounded-lg transition-colors"
                                  title="Modify Risk"
                                >
                                  <Edit2 className="w-4 h-4 opacity-50" />
                                </button>
                                <button 
                                  onClick={() => handleArchiveRisk(risk)}
                                  className="p-2 hover:bg-ink/5 rounded-lg transition-colors"
                                  title="Archive Risk"
                                >
                                  <BookOpen className="w-4 h-4 opacity-50" />
                                </button>
                                <button 
                                  onClick={() => handleRemoveRisk(risk.id)}
                                  className="p-2 hover:bg-red-500/10 text-red-500 rounded-lg transition-colors"
                                  title="Remove Risk"
                                >
                                  <Trash2 className="w-4 h-4" />
                                </button>
                              </div>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {risks.filter(r => !r.archived).length === 0 && (
                    <div className="p-24 text-center">
                      <Activity className="w-12 h-12 opacity-10 mx-auto mb-4" />
                      <p className="text-sm opacity-30 italic">No active risks identified.</p>
                    </div>
                  )}
                </div>

                {risks.some(r => r.archived) && (
                  <div className="space-y-4">
                    <h3 className="text-[10px] font-mono uppercase tracking-widest opacity-30">Archived Risks</h3>
                    <div className="border border-line bg-card/50 opacity-60">
                      <table className="w-full text-left border-collapse">
                        <tbody className="divide-y divide-line">
                          {risks.filter(r => r.archived).map((risk) => (
                            <tr key={risk.id} className="hover:bg-ink/[0.02] transition-colors group">
                              <td className="p-4">
                                <div className="font-bold text-sm line-through opacity-50">{risk.name}</div>
                              </td>
                              <td className="p-4 text-right">
                                <button 
                                  onClick={() => handleArchiveRisk(risk)}
                                  className="text-[10px] font-bold uppercase tracking-widest hover:underline"
                                >
                                  Restore
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </motion.div>
            )}

            {activeTool === 'compliance' && (
              <motion.div
                key="compliance-tool"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-8"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-3xl font-serif italic mb-2">Compliance Tracker</h2>
                    <p className="text-sm opacity-50">Track and manage your compliance status against various frameworks.</p>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="relative">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 opacity-50" />
                      <input
                        type="text"
                        placeholder="Search controls..."
                        value={complianceSearch}
                        onChange={(e) => setComplianceSearch(e.target.value)}
                        className="pl-9 pr-4 py-2 bg-transparent border border-line rounded-lg text-sm focus:outline-none focus:border-ink w-64 transition-colors"
                      />
                    </div>
                  </div>
                </div>

                {/* Framework Selector */}
                <div className="flex items-center gap-2 overflow-x-auto pb-2 border-b border-line">
                  {Object.keys(FRAMEWORKS).map(framework => (
                    <button
                      key={framework}
                      onClick={() => setActiveFramework(framework)}
                      className={cn(
                        "px-4 py-2 text-sm font-medium whitespace-nowrap transition-colors border-b-2",
                        activeFramework === framework 
                          ? "border-ink text-ink" 
                          : "border-transparent opacity-50 hover:opacity-100"
                      )}
                    >
                      {framework}
                    </button>
                  ))}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="p-6 border border-line bg-card/50 rounded-xl flex flex-col justify-between">
                    <div className="text-[10px] font-mono uppercase tracking-widest opacity-50 mb-4">Overall Progress</div>
                    <div className="flex items-end gap-2">
                      <div className="text-4xl font-light">{complianceProgress.percentage}%</div>
                      <div className="text-sm opacity-50 mb-1">implemented</div>
                    </div>
                    <div className="w-full h-1 bg-line mt-4 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-emerald-500 transition-all duration-500" 
                        style={{ width: `${complianceProgress.percentage}%` }}
                      />
                    </div>
                  </div>
                  
                  <div className="p-6 border border-line bg-card/50 rounded-xl flex flex-col justify-between">
                    <div className="text-[10px] font-mono uppercase tracking-widest opacity-50 mb-4">Implemented</div>
                    <div className="text-4xl font-light text-emerald-600 dark:text-emerald-400">{complianceProgress.implemented}</div>
                    <div className="text-xs opacity-50 mt-2">Controls fully met</div>
                  </div>

                  <div className="p-6 border border-line bg-card/50 rounded-xl flex flex-col justify-between">
                    <div className="text-[10px] font-mono uppercase tracking-widest opacity-50 mb-4">In Progress</div>
                    <div className="text-4xl font-light text-amber-600 dark:text-amber-400">{complianceProgress.inProgress}</div>
                    <div className="text-xs opacity-50 mt-2">Controls being worked on</div>
                  </div>

                  <div className="p-6 border border-line bg-card/50 rounded-xl flex flex-col justify-between">
                    <div className="text-[10px] font-mono uppercase tracking-widest opacity-50 mb-4">Not Started</div>
                    <div className="text-4xl font-light">{complianceProgress.total - complianceProgress.implemented - complianceProgress.inProgress - complianceProgress.notApplicable}</div>
                    <div className="text-xs opacity-50 mt-2">Controls pending action</div>
                  </div>
                </div>

                <div className="border border-line bg-card/50 rounded-xl overflow-hidden">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-line bg-ink/5">
                        <th className="p-4 text-[10px] font-mono uppercase tracking-widest opacity-50 font-normal">ID</th>
                        <th className="p-4 text-[10px] font-mono uppercase tracking-widest opacity-50 font-normal">Group</th>
                        <th className="p-4 text-[10px] font-mono uppercase tracking-widest opacity-50 font-normal">Title</th>
                        <th className="p-4 text-[10px] font-mono uppercase tracking-widest opacity-50 font-normal">Description</th>
                        <th className="p-4 text-[10px] font-mono uppercase tracking-widest opacity-50 font-normal text-right">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line">
                      {filteredControls.map((item) => (
                        <tr key={item.id} className="hover:bg-ink/[0.02] transition-colors">
                          <td className="p-4">
                            <div className="font-mono text-xs font-bold">{item.id}</div>
                          </td>
                          <td className="p-4">
                            <div className="inline-flex items-center px-2 py-1 rounded-full text-[10px] font-bold uppercase tracking-widest bg-ink/5">
                              {item.group}
                            </div>
                          </td>
                          <td className="p-4">
                            <div className="text-sm font-medium">{item.title}</div>
                          </td>
                          <td className="p-4 max-w-md">
                            <div className="text-xs opacity-70 line-clamp-2" title={item.description}>{item.description}</div>
                          </td>
                          <td className="p-4 text-right">
                            <select
                              value={complianceStatuses[activeFramework]?.[item.id] || 'Not Started'}
                              onChange={(e) => handleUpdateCompliance(activeFramework, item.id, e.target.value as ComplianceStatus)}
                              className={cn(
                                "text-xs font-medium bg-transparent border border-line rounded px-2 py-1 focus:outline-none focus:border-ink cursor-pointer",
                                (complianceStatuses[activeFramework]?.[item.id] || 'Not Started') === 'Implemented' && "text-emerald-600 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800",
                                (complianceStatuses[activeFramework]?.[item.id] || 'Not Started') === 'In Progress' && "text-amber-600 dark:text-amber-400 border-amber-200 dark:border-amber-800",
                                (complianceStatuses[activeFramework]?.[item.id] || 'Not Started') === 'Not Applicable' && "opacity-50"
                              )}
                            >
                              <option value="Not Started">Not Started</option>
                              <option value="In Progress">In Progress</option>
                              <option value="Implemented">Implemented</option>
                              <option value="Not Applicable">Not Applicable</option>
                            </select>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {filteredControls.length === 0 && (
                    <div className="p-8 text-center">
                      <p className="text-sm opacity-50">No controls found matching your search.</p>
                    </div>
                  )}
                </div>
              </motion.div>
            )}

            {activeTool === 'pentest' && (
              <motion.div
                key="pentest-tool"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-8"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-3xl font-serif italic">Pentest Results</h2>
                    <p className="text-sm opacity-50 mt-1">Track and remediate vulnerabilities from internal and external security assessments.</p>
                  </div>
                  <button 
                    onClick={() => setIsAddingPentest(true)}
                    className="flex items-center gap-2 px-4 py-2 bg-ink text-bg text-[10px] font-bold uppercase tracking-widest hover:opacity-90 transition-all"
                  >
                    <Plus className="w-3 h-3" />
                    Add Result
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="p-4 border border-line bg-card flex flex-col items-center justify-center text-center space-y-1">
                    <p className="text-[10px] uppercase tracking-widest opacity-50">Total Findings</p>
                    <p className="text-2xl font-light">{pentestResults.length}</p>
                  </div>
                  <div className="p-4 border border-line bg-card flex flex-col items-center justify-center text-center space-y-1">
                    <p className="text-[10px] uppercase tracking-widest opacity-50 text-red-500">Critical/High</p>
                    <p className="text-2xl font-light text-red-500">
                      {pentestResults.filter(r => r.severity === 'Critical' || r.severity === 'High').length}
                    </p>
                  </div>
                  <div className="p-4 border border-line bg-card flex flex-col items-center justify-center text-center space-y-1">
                    <p className="text-[10px] uppercase tracking-widest opacity-50 text-orange-500">Open</p>
                    <p className="text-2xl font-light text-orange-500">
                      {pentestResults.filter(r => r.status === 'Open').length}
                    </p>
                  </div>
                  <div className="p-4 border border-line bg-card flex flex-col items-center justify-center text-center space-y-1">
                    <p className="text-[10px] uppercase tracking-widest opacity-50 text-green-500">Resolved</p>
                    <p className="text-2xl font-light text-green-500">
                      {pentestResults.filter(r => r.status === 'Resolved').length}
                    </p>
                  </div>
                </div>

                <div className="border border-line bg-card overflow-hidden">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-bottom border-line bg-bg/50">
                        <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest opacity-50">Finding</th>
                        <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest opacity-50">Severity</th>
                        <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest opacity-50">Source</th>
                        <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest opacity-50">Assignment</th>
                        <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest opacity-50">Status</th>
                        <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest opacity-50">Date</th>
                        <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest opacity-50 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line">
                      {pentestResults.map((result) => (
                        <tr key={result.id} className="hover:bg-bg/30 transition-colors group">
                          <td className="px-6 py-4">
                            <div className="space-y-1">
                              <p className="text-sm font-medium">{result.title}</p>
                              <p className="text-xs opacity-50 line-clamp-1">{result.description}</p>
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            <span className={cn(
                              "px-2 py-1 text-[10px] font-bold uppercase tracking-widest rounded-full",
                              result.severity === 'Critical' ? "bg-red-500 text-white" :
                              result.severity === 'High' ? "bg-orange-500 text-white" :
                              result.severity === 'Medium' ? "bg-yellow-500 text-ink" :
                              "bg-blue-500 text-white"
                            )}>
                              {result.severity}
                            </span>
                          </td>
                          <td className="px-6 py-4">
                            <span className="text-xs opacity-60">{result.source}</span>
                          </td>
                          <td className="px-6 py-4">
                            <span className="text-xs font-medium opacity-80">{result.assignment || 'Unassigned'}</span>
                          </td>
                          <td className="px-6 py-4">
                            <span className={cn(
                              "text-xs font-medium",
                              result.status === 'Open' ? "text-red-500" :
                              result.status === 'In Progress' ? "text-orange-500" :
                              "text-green-500"
                            )}>
                              {result.status}
                            </span>
                          </td>
                          <td className="px-6 py-4">
                            <span className="text-xs font-mono opacity-50">{result.date}</span>
                          </td>
                          <td className="px-6 py-4 text-right">
                            <div className="flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                              <button 
                                onClick={() => {
                                  setEditingPentest(result);
                                  setNewPentest(result);
                                  setIsAddingPentest(true);
                                }}
                                className="p-2 hover:bg-ink hover:text-bg transition-colors rounded"
                              >
                                <Edit2 className="w-3 h-3" />
                              </button>
                              <button 
                                onClick={() => handleDeletePentest(result.id)}
                                className="p-2 hover:bg-red-500 hover:text-white transition-colors rounded"
                              >
                                <Trash2 className="w-3 h-3" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                      {pentestResults.length === 0 && (
                        <tr>
                          <td colSpan={6} className="px-6 py-12 text-center">
                            <div className="flex flex-col items-center justify-center space-y-3">
                              <Bug className="w-8 h-8 opacity-10" />
                              <p className="text-sm opacity-50 italic">No pentest results recorded yet.</p>
                            </div>
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>

                <AnimatePresence>
                  {isAddingPentest && (
                    <motion.div 
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      className="fixed inset-0 bg-ink/40 backdrop-blur-sm z-50 flex items-center justify-center p-4"
                    >
                      <motion.div 
                        initial={{ scale: 0.95, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        exit={{ scale: 0.95, opacity: 0 }}
                        className="bg-bg border border-line w-full max-w-lg p-8 space-y-6 shadow-2xl"
                      >
                        <div className="flex items-center justify-between">
                          <h3 className="text-2xl font-serif italic">{editingPentest ? 'Edit Finding' : 'Add Finding'}</h3>
                          <button onClick={() => {
                            setIsAddingPentest(false);
                            setEditingPentest(null);
                            setNewPentest({
                              title: '',
                              description: '',
                              severity: 'Medium',
                              status: 'Open',
                              source: 'Internal',
                              date: new Date().toISOString().split('T')[0],
                              assignment: '',
                              remediationPlan: ''
                            });
                          }} className="p-2 hover:bg-ink/5 transition-colors">
                            <X className="w-4 h-4" />
                          </button>
                        </div>

                        <div className="space-y-4">
                          <div className="space-y-1.5">
                            <label className="text-[10px] font-bold uppercase tracking-widest opacity-50">Title</label>
                            <input 
                              type="text" 
                              value={newPentest.title}
                              onChange={e => setNewPentest(prev => ({ ...prev, title: e.target.value }))}
                              className="w-full px-4 py-3 bg-transparent border border-line focus:border-ink outline-none transition-colors text-sm"
                              placeholder="e.g., SQL Injection in Login Form"
                            />
                          </div>
                          <div className="space-y-1.5">
                            <label className="text-[10px] font-bold uppercase tracking-widest opacity-50">Description</label>
                            <textarea 
                              value={newPentest.description}
                              onChange={e => setNewPentest(prev => ({ ...prev, description: e.target.value }))}
                              className="w-full px-4 py-3 bg-transparent border border-line focus:border-ink outline-none transition-colors text-sm min-h-[100px] resize-none"
                              placeholder="Describe the vulnerability..."
                            />
                          </div>
                          <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-1.5">
                              <label className="text-[10px] font-bold uppercase tracking-widest opacity-50">Severity</label>
                              <select 
                                value={newPentest.severity}
                                onChange={e => setNewPentest(prev => ({ ...prev, severity: e.target.value as any }))}
                                className="w-full px-4 py-3 bg-transparent border border-line focus:border-ink outline-none transition-colors text-sm"
                              >
                                <option value="Low">Low</option>
                                <option value="Medium">Medium</option>
                                <option value="High">High</option>
                                <option value="Critical">Critical</option>
                              </select>
                            </div>
                            <div className="space-y-1.5">
                              <label className="text-[10px] font-bold uppercase tracking-widest opacity-50">Status</label>
                              <select 
                                value={newPentest.status}
                                onChange={e => setNewPentest(prev => ({ ...prev, status: e.target.value as any }))}
                                className="w-full px-4 py-3 bg-transparent border border-line focus:border-ink outline-none transition-colors text-sm"
                              >
                                <option value="Open">Open</option>
                                <option value="In Progress">In Progress</option>
                                <option value="Resolved">Resolved</option>
                              </select>
                            </div>
                          </div>
                          <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-1.5">
                              <label className="text-[10px] font-bold uppercase tracking-widest opacity-50">Source</label>
                              <select 
                                value={newPentest.source}
                                onChange={e => setNewPentest(prev => ({ ...prev, source: e.target.value as any }))}
                                className="w-full px-4 py-3 bg-transparent border border-line focus:border-ink outline-none transition-colors text-sm"
                              >
                                <option value="Internal">Internal (Red Team)</option>
                                <option value="External">External (Security Co)</option>
                              </select>
                            </div>
                            <div className="space-y-1.5">
                              <label className="text-[10px] font-bold uppercase tracking-widest opacity-50">Date</label>
                              <input 
                                type="date" 
                                value={newPentest.date}
                                onChange={e => setNewPentest(prev => ({ ...prev, date: e.target.value }))}
                                className="w-full px-4 py-3 bg-transparent border border-line focus:border-ink outline-none transition-colors text-sm"
                              />
                            </div>
                          </div>

                          <div className="space-y-1.5">
                            <label className="text-[10px] font-bold uppercase tracking-widest opacity-50">Assignment (Technical Team)</label>
                            <input 
                              type="text" 
                              value={newPentest.assignment}
                              onChange={e => setNewPentest(prev => ({ ...prev, assignment: e.target.value }))}
                              className="w-full px-4 py-3 bg-transparent border border-line focus:border-ink outline-none transition-colors text-sm"
                              placeholder="e.g., Cloud Infrastructure Team"
                            />
                          </div>
                        </div>

                        <button 
                          onClick={handleAddPentest}
                          className="w-full py-4 bg-ink text-bg font-bold uppercase tracking-widest hover:opacity-90 transition-all"
                        >
                          {editingPentest ? 'Save Changes' : 'Add Finding'}
                        </button>
                      </motion.div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            )}

            {activeTool === 'vulnerability' && (
              <motion.div
                key="vulnerability-tool"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-8"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-3xl font-serif italic">Vulnerability Management</h2>
                    <p className="text-xs opacity-50 mt-1">Import and track Nessus vulnerability scans.</p>
                  </div>
                  <div className="flex gap-4">
                    <input 
                      type="file" 
                      ref={nessusFileInputRef} 
                      onChange={handleNessusUpload} 
                      className="hidden" 
                      accept=".csv"
                    />
                    <button 
                      onClick={() => nessusFileInputRef.current?.click()}
                      disabled={isProcessing}
                      className="px-6 py-3 bg-ink text-bg text-xs font-bold uppercase tracking-widest hover:opacity-90 transition-all flex items-center gap-2 disabled:opacity-50"
                    >
                      {isProcessing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
                      Import Nessus CSV
                    </button>
                  </div>
                </div>

                {globalError && (
                  <div className="p-4 bg-red-500/10 border border-red-500/20 text-red-500 text-sm flex items-center gap-2">
                    <AlertCircle className="w-4 h-4" />
                    {globalError}
                  </div>
                )}

                <div className="grid grid-cols-4 gap-6">
                  <div className="p-6 border border-line bg-card">
                    <p className="text-[10px] uppercase tracking-widest opacity-50 mb-2 font-mono">Critical</p>
                    <h3 className="text-4xl font-serif italic text-red-500">
                      {vulnerabilities.filter(v => v.severity === 'Critical' && v.status === 'Open').length}
                    </h3>
                  </div>
                  <div className="p-6 border border-line bg-card">
                    <p className="text-[10px] uppercase tracking-widest opacity-50 mb-2 font-mono">High</p>
                    <h3 className="text-4xl font-serif italic text-orange-500">
                      {vulnerabilities.filter(v => v.severity === 'High' && v.status === 'Open').length}
                    </h3>
                  </div>
                  <div className="p-6 border border-line bg-card">
                    <p className="text-[10px] uppercase tracking-widest opacity-50 mb-2 font-mono">Medium</p>
                    <h3 className="text-4xl font-serif italic text-amber-500">
                      {vulnerabilities.filter(v => v.severity === 'Medium' && v.status === 'Open').length}
                    </h3>
                  </div>
                  <div className="p-6 border border-line bg-card">
                    <p className="text-[10px] uppercase tracking-widest opacity-50 mb-2 font-mono">Low / Info</p>
                    <h3 className="text-4xl font-serif italic text-blue-500">
                      {vulnerabilities.filter(v => (v.severity === 'Low' || v.severity === 'Info') && v.status === 'Open').length}
                    </h3>
                  </div>
                </div>

                <div className="border border-line bg-card overflow-hidden">
                  <div className="p-4 border-b border-line bg-ink/5 flex items-center gap-4">
                    <Radar className="w-5 h-5 opacity-50" />
                    <h3 className="font-bold uppercase tracking-widest text-sm">Open Vulnerabilities</h3>
                  </div>
                  <div className="max-h-[600px] overflow-y-auto">
                    {vulnerabilities.filter(v => v.status === 'Open').length === 0 ? (
                      <div className="p-12 text-center space-y-4">
                        <p className="opacity-50 text-sm italic">
                          No open vulnerabilities found. Import a Nessus scan to get started.
                        </p>
                        <button
                          onClick={handleSeedDemoVulnerabilities}
                          disabled={isProcessing}
                          className="px-6 py-2 bg-ink/5 hover:bg-ink/10 text-ink text-xs font-bold uppercase tracking-widest transition-colors rounded-lg disabled:opacity-50"
                        >
                          {isProcessing ? 'Seeding...' : 'Seed Demo Vulnerabilities'}
                        </button>
                      </div>
                    ) : (
                      <table className="w-full text-left border-collapse">
                        <thead className="sticky top-0 bg-card z-10 shadow-sm">
                          <tr className="border-b border-line text-[10px] uppercase tracking-widest opacity-50">
                            <th className="p-4 font-medium whitespace-nowrap">Severity</th>
                            <th className="p-4 font-medium whitespace-nowrap">IP / Host</th>
                            <th className="p-4 font-medium whitespace-nowrap">Agent / Plugin</th>
                            <th className="p-4 font-medium">Title</th>
                            <th className="p-4 font-medium">Description</th>
                            <th className="p-4 font-medium whitespace-nowrap">Age</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-line">
                          {vulnerabilities.filter(v => v.status === 'Open').map((vuln) => {
                            const ageInDays = Math.max(0, Math.floor((new Date().getTime() - new Date(vuln.firstSeen).getTime()) / (1000 * 60 * 60 * 24)));
                            
                            return (
                              <tr key={vuln.id} className="hover:bg-ink/5 transition-colors group align-top">
                                <td className="p-4 whitespace-nowrap">
                                  <span className={cn(
                                    "px-2 py-1 text-[10px] font-bold uppercase tracking-widest inline-block",
                                    vuln.severity === 'Critical' ? "bg-red-500/10 text-red-500" :
                                    vuln.severity === 'High' ? "bg-orange-500/10 text-orange-500" :
                                    vuln.severity === 'Medium' ? "bg-amber-500/10 text-amber-500" :
                                    vuln.severity === 'Low' ? "bg-blue-500/10 text-blue-500" :
                                    "bg-slate-500/10 text-slate-500"
                                  )}>
                                    {vuln.severity}
                                  </span>
                                </td>
                                <td className="p-4 whitespace-nowrap">
                                  <div className="text-sm font-mono">{vuln.host}</div>
                                  <div className="text-[10px] opacity-50 font-mono mt-1">Port: {vuln.port}</div>
                                </td>
                                <td className="p-4 whitespace-nowrap">
                                  <div className="text-sm font-mono">{vuln.pluginId}</div>
                                </td>
                                <td className="p-4">
                                  <div className="text-sm font-bold line-clamp-2">{vuln.pluginName}</div>
                                </td>
                                <td className="p-4">
                                  <div className="text-xs opacity-70 line-clamp-2 max-w-md">{vuln.description}</div>
                                </td>
                                <td className="p-4 whitespace-nowrap">
                                  <div className={cn(
                                    "px-2 py-0.5 text-[10px] font-bold uppercase tracking-widest rounded-full border inline-block",
                                    ageInDays > 90 ? "border-red-500/30 text-red-500 bg-red-500/5" :
                                    ageInDays > 30 ? "border-orange-500/30 text-orange-500 bg-orange-500/5" :
                                    "border-ink/20 text-ink/70"
                                  )}>
                                    {ageInDays} {ageInDays === 1 ? 'Day' : 'Days'}
                                  </div>
                                  <div className="text-[10px] opacity-50 font-mono mt-1">
                                    {new Date(vuln.firstSeen).toLocaleDateString()}
                                  </div>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    )}
                  </div>
                </div>
              </motion.div>
            )}

            {activeTool === 'resilience' && (
              <motion.div
                key="resilience-tool"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-8"
              >
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <h2 className="text-2xl font-serif italic">Resilience Dashboard</h2>
                    <p className="text-sm opacity-60">Monitor backup status and disaster recovery replication.</p>
                  </div>
                  {resilienceLoading && (
                    <div className="flex items-center gap-2 text-sm opacity-60">
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span>Syncing with APIs...</span>
                    </div>
                  )}
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  {/* Server Backups */}
                  <div className="col-span-1 lg:col-span-2 bg-white rounded-2xl border border-line p-6 shadow-sm">
                    <div className="flex items-center justify-between mb-6">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-full bg-indigo-50 flex items-center justify-center text-indigo-600">
                          <Server className="w-5 h-5" />
                        </div>
                        <div>
                          <h3 className="font-medium">Daily Server Backups</h3>
                          <p className="text-xs opacity-60">Last 24 hours</p>
                        </div>
                      </div>
                      <div className="flex gap-4 text-sm">
                        <div className="flex items-center gap-1.5">
                          <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                          <span>{serverBackups.filter(b => b.status === 'Success').length} Successful</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <XCircle className="w-4 h-4 text-rose-500" />
                          <span>{serverBackups.filter(b => b.status !== 'Success').length} Failed</span>
                        </div>
                      </div>
                    </div>
                    
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm text-left">
                        <thead className="text-xs uppercase opacity-60 border-b border-line">
                          <tr>
                            <th className="pb-3 font-medium">Server</th>
                            <th className="pb-3 font-medium">Status</th>
                            <th className="pb-3 font-medium">Last Backup</th>
                            <th className="pb-3 font-medium">Size</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-line">
                          {serverBackups.map((backup) => (
                            <tr key={backup.id} className="group">
                              <td className="py-3 font-medium">{backup.name}</td>
                              <td className="py-3">
                                <span className={cn(
                                  "inline-flex items-center gap-1.5 px-2 py-1 rounded-full text-[10px] font-medium uppercase tracking-wider",
                                  backup.status === 'Success' ? "bg-emerald-50 text-emerald-700" : "bg-rose-50 text-rose-700"
                                )}>
                                  {backup.status === 'Success' ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
                                  {backup.status}
                                </span>
                              </td>
                              <td className="py-3 opacity-80">{backup.lastBackup}</td>
                              <td className="py-3 opacity-80">{backup.size}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* End User Backups */}
                  <div className="col-span-1 bg-white rounded-2xl border border-line p-6 shadow-sm">
                    <div className="flex items-center gap-3 mb-6">
                      <div className="w-10 h-10 rounded-full bg-sky-50 flex items-center justify-center text-sky-600">
                        <Cloud className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="font-medium">End User Backups</h3>
                        <p className="text-xs opacity-60">OneDrive Sync Status</p>
                      </div>
                    </div>

                    <div className="space-y-4">
                      {endUserBackups.map((user) => (
                        <div key={user.id} className="flex items-center justify-between p-3 rounded-xl border border-line/50 bg-ink/[0.02]">
                          <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-full bg-ink/10 flex items-center justify-center text-xs font-medium">
                              {user.name.charAt(0)}
                            </div>
                            <div>
                              <p className="text-sm font-medium">{user.name}</p>
                              <p className="text-[10px] opacity-60">{user.lastSync}</p>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-medium opacity-60">{user.usage}</span>
                            {user.status === 'Synced' && <CheckCircle2 className="w-4 h-4 text-emerald-500" />}
                            {user.status === 'Warning' && <AlertCircle className="w-4 h-4 text-amber-500" />}
                            {user.status === 'Error' && <XCircle className="w-4 h-4 text-rose-500" />}
                          </div>
                        </div>
                      ))}
                    </div>
                    <button className="w-full mt-4 py-2 text-xs font-medium text-sky-600 hover:bg-sky-50 rounded-lg transition-colors">
                      View All Users
                    </button>
                  </div>

                  {/* DR Replication */}
                  <div className="col-span-1 lg:col-span-3 bg-white rounded-2xl border border-line p-6 shadow-sm">
                    <div className="flex items-center gap-3 mb-6">
                      <div className="w-10 h-10 rounded-full bg-violet-50 flex items-center justify-center text-violet-600">
                        <ArrowRightLeft className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="font-medium">Disaster Recovery Replication</h3>
                        <p className="text-xs opacity-60">Primary to DR Site Sync</p>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                      {drReplication.map((rep) => (
                        <div key={rep.id} className="p-4 rounded-xl border border-line relative overflow-hidden group hover:border-violet-200 transition-colors">
                          <div className={cn(
                            "absolute top-0 left-0 w-1 h-full",
                            rep.status === 'Healthy' ? "bg-emerald-500" : rep.status === 'Lagging' ? "bg-amber-500" : "bg-rose-500"
                          )} />
                          <div className="flex justify-between items-start mb-4">
                            <span className={cn(
                              "inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider",
                              rep.status === 'Healthy' ? "bg-emerald-50 text-emerald-700" : rep.status === 'Lagging' ? "bg-amber-50 text-amber-700" : "bg-rose-50 text-rose-700"
                            )}>
                              {rep.status}
                            </span>
                            <span className="text-[10px] font-medium opacity-50 uppercase tracking-wider">{rep.type}</span>
                          </div>
                          
                          <div className="space-y-3">
                            <div>
                              <p className="text-[10px] uppercase tracking-wider opacity-50 mb-1">Source</p>
                              <p className="text-sm font-medium flex items-center gap-1.5">
                                <Database className="w-3.5 h-3.5 opacity-50" />
                                {rep.source}
                              </p>
                            </div>
                            <div className="flex justify-center">
                              <ArrowRightLeft className="w-4 h-4 opacity-20" />
                            </div>
                            <div>
                              <p className="text-[10px] uppercase tracking-wider opacity-50 mb-1">Target</p>
                              <p className="text-sm font-medium flex items-center gap-1.5">
                                <Database className="w-3.5 h-3.5 opacity-50" />
                                {rep.target}
                              </p>
                            </div>
                          </div>
                          
                          <div className="mt-4 pt-3 border-t border-line flex justify-between items-center">
                            <span className="text-xs opacity-60">Replication Lag</span>
                            <span className="text-sm font-mono font-medium">{rep.lag}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </motion.div>
            )}

            {activeTool === 'scorecard' && (
              <motion.div
                key="scorecard-tool"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-8"
              >
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <h2 className="text-2xl font-serif italic">Security Scorecard</h2>
                    <p className="text-sm opacity-60">Monitor your external security posture and vulnerabilities.</p>
                  </div>
                  <div className="flex items-center gap-4">
                    <input
                      type="text"
                      placeholder="Enter domain (e.g. example.com)"
                      value={scorecardDomain}
                      onChange={(e) => setScorecardDomain(e.target.value)}
                      className="px-4 py-2 border border-line bg-card text-sm focus:outline-none w-64"
                      onKeyDown={(e) => e.key === 'Enter' && fetchScorecardData(scorecardDomain)}
                    />
                    <button
                      onClick={() => fetchScorecardData(scorecardDomain)}
                      disabled={isFetchingScorecard || !scorecardDomain}
                      className="px-6 py-2 bg-ink text-bg text-xs font-bold uppercase tracking-widest hover:opacity-90 transition-all disabled:opacity-50 flex items-center gap-2"
                    >
                      {isFetchingScorecard ? <Loader2 className="w-4 h-4 animate-spin" /> : <BarChart3 className="w-4 h-4" />}
                      Fetch Score
                    </button>
                  </div>
                </div>

                {scorecardError && (
                  <div className="p-4 bg-red-500/10 border border-red-500/20 text-red-500 text-sm flex items-center gap-2">
                    <AlertCircle className="w-4 h-4" />
                    {scorecardError}
                  </div>
                )}

                {!scorecardData && !isFetchingScorecard && !scorecardError && (
                  <div className="flex flex-col items-center justify-center min-h-[40vh] text-center space-y-6 opacity-50">
                    <div className="w-20 h-20 bg-ink/5 rounded-full flex items-center justify-center">
                      <BarChart3 className="w-10 h-10 opacity-20" />
                    </div>
                    <p className="text-sm max-w-md mx-auto">
                      Enter a domain above to fetch its Security Scorecard rating, factors, and active issues.
                    </p>
                  </div>
                )}

                {scorecardData && (
                  <div className="space-y-8">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                      <div className="col-span-1 p-8 border border-line bg-card flex flex-col items-center justify-center text-center">
                        <p className="text-[10px] uppercase tracking-widest opacity-50 mb-4 font-mono">Overall Grade</p>
                        <div className={cn(
                          "w-32 h-32 rounded-full flex items-center justify-center text-6xl font-serif italic border-4",
                          scorecardData.company?.grade === 'A' ? "border-green-500 text-green-500" :
                          scorecardData.company?.grade === 'B' ? "border-blue-500 text-blue-500" :
                          scorecardData.company?.grade === 'C' ? "border-amber-500 text-amber-500" :
                          scorecardData.company?.grade === 'D' ? "border-orange-500 text-orange-500" :
                          "border-red-500 text-red-500"
                        )}>
                          {scorecardData.company?.grade || '?'}
                        </div>
                        <h3 className="text-2xl font-bold mt-6">{scorecardData.company?.score || 0} / 100</h3>
                        <p className="text-sm opacity-60 mt-2">{scorecardData.company?.domain}</p>
                      </div>
                      
                      <div className="col-span-2 grid grid-cols-2 gap-4">
                        {scorecardData.factors?.map((factor: any) => (
                          <div key={factor.name} className="p-4 border border-line bg-card flex items-center justify-between">
                            <div>
                              <p className="text-sm font-medium capitalize">{factor.name.replace(/_/g, ' ')}</p>
                              <p className="text-[10px] uppercase tracking-widest opacity-50 font-mono mt-1">Score: {factor.score}</p>
                            </div>
                            <div className={cn(
                              "w-10 h-10 rounded flex items-center justify-center text-lg font-bold",
                              factor.grade === 'A' ? "bg-green-500/10 text-green-500" :
                              factor.grade === 'B' ? "bg-blue-500/10 text-blue-500" :
                              factor.grade === 'C' ? "bg-amber-500/10 text-amber-500" :
                              factor.grade === 'D' ? "bg-orange-500/10 text-orange-500" :
                              "bg-red-500/10 text-red-500"
                            )}>
                              {factor.grade}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="border border-line bg-card overflow-hidden">
                      <div className="p-4 border-b border-line bg-ink/5 flex items-center gap-4">
                        <AlertCircle className="w-5 h-5 opacity-50" />
                        <h3 className="font-bold uppercase tracking-widest text-sm">Active Issues & Vulnerabilities</h3>
                      </div>
                      <div className="divide-y divide-line max-h-[400px] overflow-y-auto">
                        {scorecardData.issues?.length === 0 ? (
                          <div className="p-8 text-center opacity-50 text-sm italic">
                            No active issues found for this domain.
                          </div>
                        ) : (
                          scorecardData.issues?.map((issue: any, idx: number) => (
                            <div key={idx} className="p-4 hover:bg-ink/5 transition-colors flex items-center justify-between">
                              <div>
                                <h4 className="font-medium text-sm capitalize">{issue.type?.replace(/_/g, ' ')}</h4>
                                <p className="text-xs opacity-60 mt-1">Severity: {issue.severity || 'Unknown'}</p>
                              </div>
                              <div className="text-right">
                                <span className="px-3 py-1 bg-ink/5 rounded-full text-xs font-mono">
                                  Count: {issue.count || 1}
                                </span>
                              </div>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </main>

      {/* Add Q&A Modal */}
      <AnimatePresence>
        {isAddingQA && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-6">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsAddingQA(false)}
              className="absolute inset-0 bg-ink/60 backdrop-blur-sm"
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.9, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.9, y: 20 }}
              className="relative w-full max-w-2xl bg-bg border border-line shadow-2xl p-12"
            >
              <h2 className="text-3xl font-serif italic mb-8">Add KB Entry</h2>
              <div className="space-y-6">
                <div>
                  <label className="text-[10px] font-mono uppercase tracking-widest opacity-50 mb-2 block">Question</label>
                  <textarea 
                    value={newQA.question}
                    onChange={(e) => setNewQA({ ...newQA, question: e.target.value })}
                    className="w-full p-4 bg-card border border-line text-sm focus:outline-none h-24 resize-none"
                    placeholder="e.g. Do you encrypt data at rest?"
                  />
                </div>
                <div>
                  <label className="text-[10px] font-mono uppercase tracking-widest opacity-50 mb-2 block">Answer</label>
                  <textarea 
                    value={newQA.answer}
                    onChange={(e) => setNewQA({ ...newQA, answer: e.target.value })}
                    className="w-full p-4 bg-card border border-line text-sm focus:outline-none h-32 resize-none"
                    placeholder="e.g. Yes, we use AES-256 encryption for all data at rest..."
                  />
                </div>
                <div className="grid grid-cols-2 gap-6">
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-widest opacity-50 mb-2 block">Category</label>
                    <select 
                      value={newQA.category}
                      onChange={(e) => setNewQA({ ...newQA, category: e.target.value })}
                      className="w-full p-4 bg-card border border-line text-sm focus:outline-none"
                    >
                      <option>General</option>
                      <option>Encryption</option>
                      <option>Access Control</option>
                      <option>Compliance</option>
                      <option>Network Security</option>
                    </select>
                  </div>
                </div>
                <div className="flex items-center justify-end gap-4 mt-8">
                  <button 
                    onClick={() => setIsAddingQA(false)}
                    className="px-8 py-4 text-xs font-bold uppercase tracking-widest hover:opacity-50 transition-opacity"
                  >
                    Cancel
                  </button>
                  <button 
                    onClick={handleAddQA}
                    className="px-8 py-4 bg-ink text-bg text-xs font-bold uppercase tracking-widest hover:scale-105 transition-transform"
                  >
                    Save Entry
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Add Risk Modal */}
      <AnimatePresence>
        {isAddingRisk && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-6">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsAddingRisk(false)}
              className="absolute inset-0 bg-ink/60 backdrop-blur-sm"
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.9, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.9, y: 20 }}
              className="relative w-full max-w-2xl bg-bg border border-line shadow-2xl p-12 overflow-y-auto max-h-[90vh]"
            >
              <h2 className="text-3xl font-serif italic mb-8">Add New Risk</h2>
              <div className="space-y-6">
                <div>
                  <label className="text-[10px] font-mono uppercase tracking-widest opacity-50 mb-2 block">Risk Name</label>
                  <input 
                    type="text"
                    value={newRisk.name}
                    onChange={(e) => setNewRisk({ ...newRisk, name: e.target.value })}
                    className="w-full p-4 bg-card border border-line text-sm focus:outline-none"
                    placeholder="e.g. Data Breach via Phishing"
                  />
                </div>
                <div>
                  <label className="text-[10px] font-mono uppercase tracking-widest opacity-50 mb-2 block">Description</label>
                  <textarea 
                    value={newRisk.description}
                    onChange={(e) => setNewRisk({ ...newRisk, description: e.target.value })}
                    className="w-full p-4 bg-card border border-line text-sm focus:outline-none h-24 resize-none"
                    placeholder="Describe the risk and its potential impact..."
                  />
                </div>
                <div className="grid grid-cols-2 gap-6">
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-widest opacity-50 mb-2 block">Likelihood</label>
                    <select 
                      value={newRisk.likelihood}
                      onChange={(e) => setNewRisk({ ...newRisk, likelihood: e.target.value as any })}
                      className="w-full p-4 bg-card border border-line text-sm focus:outline-none"
                    >
                      <option>Low</option>
                      <option>Medium</option>
                      <option>High</option>
                      <option>Critical</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-widest opacity-50 mb-2 block">Risk Owner</label>
                    <input 
                      type="text"
                      value={newRisk.owner}
                      onChange={(e) => setNewRisk({ ...newRisk, owner: e.target.value })}
                      className="w-full p-4 bg-card border border-line text-sm focus:outline-none"
                      placeholder="e.g. IT Security Team"
                    />
                  </div>
                </div>
                <div>
                  <label className="text-[10px] font-mono uppercase tracking-widest opacity-50 mb-2 block">Mitigations</label>
                  <textarea 
                    value={newRisk.mitigations}
                    onChange={(e) => setNewRisk({ ...newRisk, mitigations: e.target.value })}
                    className="w-full p-4 bg-card border border-line text-sm focus:outline-none h-24 resize-none"
                    placeholder="List planned or implemented mitigations..."
                  />
                </div>
                <div className="flex items-center justify-end gap-4 mt-8">
                  <button 
                    onClick={() => setIsAddingRisk(false)}
                    className="px-8 py-4 text-xs font-bold uppercase tracking-widest hover:opacity-50 transition-opacity"
                  >
                    Cancel
                  </button>
                  <button 
                    onClick={handleAddRisk}
                    className="px-8 py-4 bg-ink text-bg text-xs font-bold uppercase tracking-widest hover:scale-105 transition-transform"
                  >
                    Create Risk
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Edit Risk Modal */}
      <AnimatePresence>
        {editingRisk && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-6">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setEditingRisk(null)}
              className="absolute inset-0 bg-ink/60 backdrop-blur-sm"
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.9, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.9, y: 20 }}
              className="relative w-full max-w-2xl bg-bg border border-line shadow-2xl p-12 overflow-y-auto max-h-[90vh]"
            >
              <h2 className="text-3xl font-serif italic mb-8">Modify Risk</h2>
              <div className="space-y-6">
                <div>
                  <label className="text-[10px] font-mono uppercase tracking-widest opacity-50 mb-2 block">Risk Name</label>
                  <input 
                    type="text"
                    value={editingRisk.name}
                    onChange={(e) => setEditingRisk({ ...editingRisk, name: e.target.value })}
                    className="w-full p-4 bg-card border border-line text-sm focus:outline-none"
                  />
                </div>
                <div>
                  <label className="text-[10px] font-mono uppercase tracking-widest opacity-50 mb-2 block">Description</label>
                  <textarea 
                    value={editingRisk.description}
                    onChange={(e) => setEditingRisk({ ...editingRisk, description: e.target.value })}
                    className="w-full p-4 bg-card border border-line text-sm focus:outline-none h-24 resize-none"
                  />
                </div>
                <div className="grid grid-cols-2 gap-6">
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-widest opacity-50 mb-2 block">Likelihood</label>
                    <select 
                      value={editingRisk.likelihood}
                      onChange={(e) => setEditingRisk({ ...editingRisk, likelihood: e.target.value as any })}
                      className="w-full p-4 bg-card border border-line text-sm focus:outline-none"
                    >
                      <option>Low</option>
                      <option>Medium</option>
                      <option>High</option>
                      <option>Critical</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-widest opacity-50 mb-2 block">Risk Owner</label>
                    <input 
                      type="text"
                      value={editingRisk.owner}
                      onChange={(e) => setEditingRisk({ ...editingRisk, owner: e.target.value })}
                      className="w-full p-4 bg-card border border-line text-sm focus:outline-none"
                    />
                  </div>
                </div>
                <div>
                  <label className="text-[10px] font-mono uppercase tracking-widest opacity-50 mb-2 block">Mitigations</label>
                  <textarea 
                    value={editingRisk.mitigations}
                    onChange={(e) => setEditingRisk({ ...editingRisk, mitigations: e.target.value })}
                    className="w-full p-4 bg-card border border-line text-sm focus:outline-none h-24 resize-none"
                  />
                </div>
                <div className="flex items-center justify-end gap-4 mt-8">
                  <button 
                    onClick={() => setEditingRisk(null)}
                    className="px-8 py-4 text-xs font-bold uppercase tracking-widest hover:opacity-50 transition-opacity"
                  >
                    Cancel
                  </button>
                  <button 
                    onClick={handleUpdateRisk}
                    className="px-8 py-4 bg-ink text-bg text-xs font-bold uppercase tracking-widest hover:scale-105 transition-transform"
                  >
                    Update Risk
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
