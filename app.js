/* ════════════════════════════════════════════════════════════
   Cyber Risk Quantification App
   ════════════════════════════════════════════════════════════ */

'use strict';

// ── Supabase ─────────────────────────────────────────────────
const SUPABASE_URL = 'https://qmcfpiddirvvpraekqku.supabase.co';
const SUPABASE_KEY = 'sb_publishable_bTy7jpRiY4GdL1k2uRy2ow_Svq6cCzb';
const TABLE = 'cyber_risk_data';

// ── Constants ─────────────────────────────────────────────────
const IMPACT_CATS = [
    { id: 'response',    label: 'Response & Mitigation' },
    { id: 'regulatory',  label: 'Regulatory' },
    { id: 'legal',       label: 'Legal' },
    { id: 'lostNewBiz',  label: 'Loss of New Business' },
    { id: 'lostExistBiz',label: 'Loss of Existing Business' },
];

const RISK_CATEGORIES = [
    'Ransomware / Extortion',
    'Data Breach / Exfiltration',
    'Business Email Compromise',
    'Insider Threat',
    'Third-Party / Supply Chain',
    'Denial of Service',
    'Physical / OT / ICS',
    'Fraud / Financial Crime',
    'Other',
];

const PERCENTILES = [10, 25, 50, 75, 90, 95, 99, 99.5];
const LOSS_INTERVALS = [
    { label: '1-in-2',   years: 2,   pct: 50   },
    { label: '1-in-5',   years: 5,   pct: 80   },
    { label: '1-in-10',  years: 10,  pct: 90   },
    { label: '1-in-20',  years: 20,  pct: 95   },
    { label: '1-in-50',  years: 50,  pct: 98   },
    { label: '1-in-100', years: 100, pct: 99   },
    { label: '1-in-200', years: 200, pct: 99.5 },
];

// ── MITRE ATT&CK v14 (curated) ────────────────────────────────
const MITRE_TACTICS = [
    { id: 'TA0043', name: 'Reconnaissance' },
    { id: 'TA0042', name: 'Resource Development' },
    { id: 'TA0001', name: 'Initial Access' },
    { id: 'TA0002', name: 'Execution' },
    { id: 'TA0003', name: 'Persistence' },
    { id: 'TA0004', name: 'Privilege Escalation' },
    { id: 'TA0005', name: 'Defense Evasion' },
    { id: 'TA0006', name: 'Credential Access' },
    { id: 'TA0007', name: 'Discovery' },
    { id: 'TA0008', name: 'Lateral Movement' },
    { id: 'TA0009', name: 'Collection' },
    { id: 'TA0011', name: 'Command & Control' },
    { id: 'TA0010', name: 'Exfiltration' },
    { id: 'TA0040', name: 'Impact' },
];

const MITRE_TECHNIQUES = [
    // Reconnaissance
    { id: 'T1595', tactic: 'TA0043', name: 'Active Scanning' },
    { id: 'T1592', tactic: 'TA0043', name: 'Gather Victim Host Info' },
    { id: 'T1589', tactic: 'TA0043', name: 'Gather Victim Identity Info' },
    { id: 'T1590', tactic: 'TA0043', name: 'Gather Victim Network Info' },
    { id: 'T1597', tactic: 'TA0043', name: 'Search Closed Sources' },
    // Resource Development
    { id: 'T1583', tactic: 'TA0042', name: 'Acquire Infrastructure' },
    { id: 'T1586', tactic: 'TA0042', name: 'Compromise Accounts' },
    { id: 'T1588', tactic: 'TA0042', name: 'Obtain Capabilities' },
    { id: 'T1584', tactic: 'TA0042', name: 'Compromise Infrastructure' },
    // Initial Access
    { id: 'T1190', tactic: 'TA0001', name: 'Exploit Public-Facing App' },
    { id: 'T1566', tactic: 'TA0001', name: 'Phishing' },
    { id: 'T1078', tactic: 'TA0001', name: 'Valid Accounts' },
    { id: 'T1199', tactic: 'TA0001', name: 'Trusted Relationship' },
    { id: 'T1195', tactic: 'TA0001', name: 'Supply Chain Compromise' },
    { id: 'T1133', tactic: 'TA0001', name: 'External Remote Services' },
    { id: 'T1189', tactic: 'TA0001', name: 'Drive-by Compromise' },
    // Execution
    { id: 'T1059', tactic: 'TA0002', name: 'Command and Scripting Interpreter' },
    { id: 'T1204', tactic: 'TA0002', name: 'User Execution' },
    { id: 'T1053', tactic: 'TA0002', name: 'Scheduled Task/Job' },
    { id: 'T1047', tactic: 'TA0002', name: 'Windows Mgmt Instrumentation' },
    // Persistence
    { id: 'T1098', tactic: 'TA0003', name: 'Account Manipulation' },
    { id: 'T1136', tactic: 'TA0003', name: 'Create Account' },
    { id: 'T1505', tactic: 'TA0003', name: 'Server Software Component' },
    { id: 'T1078', tactic: 'TA0003', name: 'Valid Accounts (Persist)' },
    { id: 'T1547', tactic: 'TA0003', name: 'Boot/Logon Autostart' },
    // Privilege Escalation
    { id: 'T1068', tactic: 'TA0004', name: 'Exploitation for Priv. Escalation' },
    { id: 'T1055', tactic: 'TA0004', name: 'Process Injection' },
    { id: 'T1548', tactic: 'TA0004', name: 'Abuse Elevation Control' },
    { id: 'T1134', tactic: 'TA0004', name: 'Access Token Manipulation' },
    // Defense Evasion
    { id: 'T1562', tactic: 'TA0005', name: 'Impair Defenses' },
    { id: 'T1070', tactic: 'TA0005', name: 'Indicator Removal' },
    { id: 'T1036', tactic: 'TA0005', name: 'Masquerading' },
    { id: 'T1027', tactic: 'TA0005', name: 'Obfuscated Files or Info' },
    { id: 'T1553', tactic: 'TA0005', name: 'Subvert Trust Controls' },
    // Credential Access
    { id: 'T1110', tactic: 'TA0006', name: 'Brute Force' },
    { id: 'T1003', tactic: 'TA0006', name: 'OS Credential Dumping' },
    { id: 'T1539', tactic: 'TA0006', name: 'Steal Web Session Cookie' },
    { id: 'T1558', tactic: 'TA0006', name: 'Steal/Forge Kerberos Tickets' },
    { id: 'T1555', tactic: 'TA0006', name: 'Credentials from Stores' },
    // Discovery
    { id: 'T1083', tactic: 'TA0007', name: 'File and Directory Discovery' },
    { id: 'T1046', tactic: 'TA0007', name: 'Network Service Discovery' },
    { id: 'T1082', tactic: 'TA0007', name: 'System Info Discovery' },
    { id: 'T1087', tactic: 'TA0007', name: 'Account Discovery' },
    // Lateral Movement
    { id: 'T1021', tactic: 'TA0008', name: 'Remote Services' },
    { id: 'T1550', tactic: 'TA0008', name: 'Use Alternate Auth Material' },
    { id: 'T1534', tactic: 'TA0008', name: 'Internal Spearphishing' },
    { id: 'T1570', tactic: 'TA0008', name: 'Lateral Tool Transfer' },
    // Collection
    { id: 'T1560', tactic: 'TA0009', name: 'Archive Collected Data' },
    { id: 'T1213', tactic: 'TA0009', name: 'Data from Info Repos' },
    { id: 'T1074', tactic: 'TA0009', name: 'Data Staged' },
    { id: 'T1119', tactic: 'TA0009', name: 'Automated Collection' },
    // Command & Control
    { id: 'T1071', tactic: 'TA0011', name: 'App Layer Protocol' },
    { id: 'T1572', tactic: 'TA0011', name: 'Protocol Tunneling' },
    { id: 'T1573', tactic: 'TA0011', name: 'Encrypted Channel' },
    { id: 'T1090', tactic: 'TA0011', name: 'Proxy' },
    // Exfiltration
    { id: 'T1048', tactic: 'TA0010', name: 'Exfil Over Alt Protocol' },
    { id: 'T1041', tactic: 'TA0010', name: 'Exfil Over C2 Channel' },
    { id: 'T1567', tactic: 'TA0010', name: 'Exfil to Cloud Service' },
    { id: 'T1537', tactic: 'TA0010', name: 'Transfer to Cloud Account' },
    // Impact
    { id: 'T1486', tactic: 'TA0040', name: 'Data Encrypted for Impact' },
    { id: 'T1490', tactic: 'TA0040', name: 'Inhibit System Recovery' },
    { id: 'T1489', tactic: 'TA0040', name: 'Service Stop' },
    { id: 'T1485', tactic: 'TA0040', name: 'Data Destruction' },
    { id: 'T1496', tactic: 'TA0040', name: 'Resource Hijacking' },
    { id: 'T1499', tactic: 'TA0040', name: 'Endpoint Denial of Service' },
    { id: 'T1657', tactic: 'TA0040', name: 'Financial Theft' },
];

// Sub-techniques (parentId links to parent technique)
const MITRE_SUBTECHNIQUES = [
    // T1595 Active Scanning
    { id: 'T1595.001', parentId: 'T1595', name: 'Scanning IP Blocks' },
    { id: 'T1595.002', parentId: 'T1595', name: 'Vulnerability Scanning' },
    { id: 'T1595.003', parentId: 'T1595', name: 'Wordlist Scanning' },
    // T1566 Phishing
    { id: 'T1566.001', parentId: 'T1566', name: 'Spearphishing Attachment' },
    { id: 'T1566.002', parentId: 'T1566', name: 'Spearphishing Link' },
    { id: 'T1566.003', parentId: 'T1566', name: 'Spearphishing via Service' },
    { id: 'T1566.004', parentId: 'T1566', name: 'Spearphishing Voice' },
    // T1078 Valid Accounts
    { id: 'T1078.001', parentId: 'T1078', name: 'Default Accounts' },
    { id: 'T1078.002', parentId: 'T1078', name: 'Domain Accounts' },
    { id: 'T1078.003', parentId: 'T1078', name: 'Local Accounts' },
    { id: 'T1078.004', parentId: 'T1078', name: 'Cloud Accounts' },
    // T1195 Supply Chain
    { id: 'T1195.001', parentId: 'T1195', name: 'Software Dependencies' },
    { id: 'T1195.002', parentId: 'T1195', name: 'Software Supply Chain' },
    { id: 'T1195.003', parentId: 'T1195', name: 'Hardware Supply Chain' },
    // T1059 Command Scripting
    { id: 'T1059.001', parentId: 'T1059', name: 'PowerShell' },
    { id: 'T1059.003', parentId: 'T1059', name: 'Windows Command Shell' },
    { id: 'T1059.005', parentId: 'T1059', name: 'Visual Basic' },
    { id: 'T1059.007', parentId: 'T1059', name: 'JavaScript' },
    // T1547 Boot/Logon Autostart
    { id: 'T1547.001', parentId: 'T1547', name: 'Registry Run Keys' },
    { id: 'T1547.004', parentId: 'T1547', name: 'Winlogon Helper DLL' },
    { id: 'T1547.009', parentId: 'T1547', name: 'Shortcut Modification' },
    // T1055 Process Injection
    { id: 'T1055.001', parentId: 'T1055', name: 'DLL Injection' },
    { id: 'T1055.003', parentId: 'T1055', name: 'Thread Execution Hijacking' },
    { id: 'T1055.012', parentId: 'T1055', name: 'Process Hollowing' },
    // T1562 Impair Defenses
    { id: 'T1562.001', parentId: 'T1562', name: 'Disable/Modify Tools' },
    { id: 'T1562.002', parentId: 'T1562', name: 'Disable Event Logging' },
    { id: 'T1562.004', parentId: 'T1562', name: 'Disable/Modify Firewall' },
    { id: 'T1562.006', parentId: 'T1562', name: 'Indicator Blocking' },
    // T1110 Brute Force
    { id: 'T1110.001', parentId: 'T1110', name: 'Password Guessing' },
    { id: 'T1110.002', parentId: 'T1110', name: 'Password Cracking' },
    { id: 'T1110.003', parentId: 'T1110', name: 'Password Spraying' },
    { id: 'T1110.004', parentId: 'T1110', name: 'Credential Stuffing' },
    // T1003 OS Credential Dumping
    { id: 'T1003.001', parentId: 'T1003', name: 'LSASS Memory' },
    { id: 'T1003.002', parentId: 'T1003', name: 'Security Account Manager' },
    { id: 'T1003.003', parentId: 'T1003', name: 'NTDS' },
    { id: 'T1003.006', parentId: 'T1003', name: 'DCSync' },
    // T1558 Kerberos
    { id: 'T1558.001', parentId: 'T1558', name: 'Golden Ticket' },
    { id: 'T1558.002', parentId: 'T1558', name: 'Silver Ticket' },
    { id: 'T1558.003', parentId: 'T1558', name: 'Kerberoasting' },
    { id: 'T1558.004', parentId: 'T1558', name: 'AS-REP Roasting' },
    // T1021 Remote Services
    { id: 'T1021.001', parentId: 'T1021', name: 'Remote Desktop Protocol' },
    { id: 'T1021.002', parentId: 'T1021', name: 'SMB / Admin Shares' },
    { id: 'T1021.004', parentId: 'T1021', name: 'SSH' },
    { id: 'T1021.006', parentId: 'T1021', name: 'Windows Remote Management' },
    // T1071 App Layer Protocol
    { id: 'T1071.001', parentId: 'T1071', name: 'Web Protocols (HTTP/S)' },
    { id: 'T1071.002', parentId: 'T1071', name: 'File Transfer Protocols' },
    { id: 'T1071.003', parentId: 'T1071', name: 'Mail Protocols' },
    { id: 'T1071.004', parentId: 'T1071', name: 'DNS' },
    // T1048 Exfiltration
    { id: 'T1048.001', parentId: 'T1048', name: 'Exfil — Symmetric Encrypted' },
    { id: 'T1048.002', parentId: 'T1048', name: 'Exfil — Asymmetric Encrypted' },
    { id: 'T1048.003', parentId: 'T1048', name: 'Exfil — Unencrypted' },
];

const MITRE_MITIGATIONS = [
    { id: 'M1049', name: 'Antivirus / Antimalware' },
    { id: 'M1047', name: 'Audit' },
    { id: 'M1048', name: 'App Isolation & Sandboxing' },
    { id: 'M1013', name: 'App Developer Guidance' },
    { id: 'M1046', name: 'Boot Integrity' },
    { id: 'M1045', name: 'Code Signing' },
    { id: 'M1043', name: 'Credential Access Protection' },
    { id: 'M1038', name: 'Execution Prevention' },
    { id: 'M1050', name: 'Exploit Protection' },
    { id: 'M1037', name: 'Filter Network Traffic' },
    { id: 'M1035', name: 'Limit Access to Resource Over Network' },
    { id: 'M1034', name: 'Limit Hardware Installation' },
    { id: 'M1033', name: 'Limit Software Installation' },
    { id: 'M1032', name: 'Multi-Factor Authentication' },
    { id: 'M1031', name: 'Network Intrusion Prevention' },
    { id: 'M1030', name: 'Network Segmentation' },
    { id: 'M1028', name: 'Operating System Configuration' },
    { id: 'M1027', name: 'Password Policies' },
    { id: 'M1026', name: 'Privileged Account Management' },
    { id: 'M1025', name: 'Privileged Process Integrity' },
    { id: 'M1024', name: 'Restrict Registry Permissions' },
    { id: 'M1022', name: 'Restrict File and Directory Permissions' },
    { id: 'M1021', name: 'Restrict Web-Based Content' },
    { id: 'M1020', name: 'SSL/TLS Inspection' },
    { id: 'M1019', name: 'Threat Intelligence Program' },
    { id: 'M1018', name: 'User Account Management' },
    { id: 'M1017', name: 'User Training' },
    { id: 'M1016', name: 'Vulnerability Scanning' },
];

// Technique → suggested mitigations mapping
const TECH_MITIGATIONS_MAP = {
    'T1595': ['M1016','M1056'],               'T1595.002': ['M1016'],
    'T1566': ['M1049','M1021','M1017','M1031'],'T1566.001': ['M1049','M1021','M1017'],
    'T1566.002': ['M1021','M1017','M1031'],   'T1566.003': ['M1017','M1021'],
    'T1566.004': ['M1017'],
    'T1078': ['M1032','M1026','M1027','M1018'],'T1078.001': ['M1027','M1026'],
    'T1078.002': ['M1032','M1026'],           'T1078.003': ['M1032','M1026'],
    'T1078.004': ['M1032','M1026','M1018'],
    'T1190': ['M1016','M1050','M1048','M1026'],'T1195': ['M1013','M1016','M1045'],
    'T1195.001': ['M1016','M1045'],           'T1195.002': ['M1013','M1045'],
    'T1195.003': ['M1046'],                   'T1133': ['M1032','M1035'],
    'T1059': ['M1038','M1045','M1026'],       'T1059.001': ['M1038','M1045'],
    'T1059.003': ['M1038'],                   'T1204': ['M1017','M1038','M1049'],
    'T1547': ['M1024','M1022'],               'T1547.001': ['M1024'],
    'T1505': ['M1026','M1045'],
    'T1068': ['M1050','M1026'],               'T1055': ['M1049','M1026'],
    'T1055.001': ['M1049'],                   'T1055.012': ['M1049'],
    'T1562': ['M1022','M1024','M1047'],       'T1562.001': ['M1022','M1024'],
    'T1562.002': ['M1022','M1047'],           'T1562.004': ['M1022'],
    'T1562.006': ['M1022','M1047'],
    'T1110': ['M1032','M1027','M1036'],       'T1110.001': ['M1032','M1027'],
    'T1110.003': ['M1032','M1027'],           'T1110.004': ['M1032','M1027'],
    'T1003': ['M1043','M1025','M1026'],       'T1003.001': ['M1043','M1025'],
    'T1003.003': ['M1026','M1047'],           'T1003.006': ['M1026','M1032'],
    'T1558': ['M1026','M1032'],               'T1558.003': ['M1026'],
    'T1021': ['M1035','M1030','M1032'],       'T1021.001': ['M1035','M1047','M1026'],
    'T1021.002': ['M1035','M1026'],           'T1021.004': ['M1042','M1032'],
    'T1550': ['M1026','M1032'],
    'T1213': ['M1032','M1022','M1018'],       'T1560': ['M1047'],
    'T1119': ['M1029','M1022'],
    'T1071': ['M1031','M1037','M1020'],       'T1071.001': ['M1031','M1020'],
    'T1071.004': ['M1037'],                   'T1572': ['M1031','M1037'],
    'T1573': ['M1020'],                       'T1090': ['M1031','M1037'],
    'T1048': ['M1037','M1031','M1020'],       'T1048.001': ['M1037','M1020'],
    'T1048.003': ['M1037'],                   'T1041': ['M1031','M1037'],
    'T1567': ['M1021','M1037'],               'T1537': ['M1032','M1022'],
    'T1486': ['M1053','M1049'],               'T1490': ['M1053','M1047'],
    'T1489': ['M1030','M1022'],               'T1485': ['M1053','M1047'],
    'T1496': ['M1049'],                       'T1499': ['M1037','M1031'],
    'T1657': ['M1026','M1047'],
};

// ══════════════════════════════════════════════════════════════
// Monte Carlo Engine
// ══════════════════════════════════════════════════════════════

function _randn() {
    // Box-Muller transform
    let u = 0, v = 0;
    while (u === 0) u = Math.random();
    while (v === 0) v = Math.random();
    return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
}

function _sampleGamma(shape, scale = 1) {
    // Marsaglia-Tsang method
    if (shape < 1) {
        return _sampleGamma(1 + shape, scale) * Math.pow(Math.random(), 1 / shape);
    }
    const d = shape - 1 / 3;
    const c = 1 / Math.sqrt(9 * d);
    for (;;) {
        let x, v;
        do {
            x = _randn();
            v = 1 + c * x;
        } while (v <= 0);
        v = v * v * v;
        const u = Math.random();
        if (u < 1 - 0.0331 * (x * x) * (x * x)) return d * v * scale;
        if (Math.log(u) < 0.5 * x * x + d * (1 - v + Math.log(v))) return d * v * scale;
    }
}

function _sampleBeta(alpha, beta) {
    if (alpha <= 0 || beta <= 0) return 0.5;
    const ga = _sampleGamma(alpha);
    const gb = _sampleGamma(beta);
    return ga / (ga + gb);
}

function _samplePert(low, ml, high) {
    if (low >= high) return ml || low;
    // PERT parameterisation
    const mean = (low + 4 * ml + high) / 6;
    const span = high - low;
    let alpha = 6 * (mean - low) / span;
    let beta  = 6 * (high - mean) / span;
    if (alpha <= 0) alpha = 0.001;
    if (beta  <= 0) beta  = 0.001;
    return low + span * _sampleBeta(alpha, beta);
}

function _percentile(sortedArr, pct) {
    if (!sortedArr.length) return 0;
    if (pct <= 0)   return sortedArr[0];
    if (pct >= 100) return sortedArr[sortedArr.length - 1];
    const idx = (pct / 100) * (sortedArr.length - 1);
    const lo  = Math.floor(idx);
    const hi  = Math.ceil(idx);
    if (lo === hi) return sortedArr[lo];
    return sortedArr[lo] + (sortedArr[hi] - sortedArr[lo]) * (idx - lo);
}

function calcControlEffectiveness(coId, controls) {
    // Sum effectiveness of all controls linked to this CO, capped at 1
    const linked = controls.filter(c => (c.linkedCOs || []).includes(coId) && c.status !== 'Inactive');
    const total = linked.reduce((sum, c) => {
        return sum + (c.design || 0) / 100 * (c.scope || 0) / 100 * (c.operating || 0) / 100;
    }, 0);
    return Math.min(total, 1);
}

function calcScenarioReductions(scenario, controlObjectives, controls) {
    const linkedCOs = (scenario.linkedCOs || []).map(id => controlObjectives.find(c => c.id === id)).filter(Boolean);
    let freqRed = 0, impactRed = 0;
    linkedCOs.forEach(co => {
        const eff = calcControlEffectiveness(co.id, controls);
        freqRed   += (co.maxFreqReduction   || 0) / 100 * eff;
        impactRed += (co.maxImpactReduction  || 0) / 100 * eff;
    });
    return {
        freqReduction:   Math.min(freqRed,   0.95),
        impactReduction: Math.min(impactRed, 0.95),
    };
}

function runMonteCarlo(scenario, controlObjectives, controls, iterations = 10000, inherent = false) {
    const { freqReduction, impactReduction } = inherent
        ? { freqReduction: 0, impactReduction: 0 }
        : calcScenarioReductions(scenario, controlObjectives, controls);

    const losses = new Float64Array(iterations);

    for (let i = 0; i < iterations; i++) {
        // Sample annual probability of occurrence
        const rawP = _samplePert(
            Math.max(0, scenario.freqLow  || 0),
            Math.max(0, scenario.freqML   || 0.1),
            Math.min(1, scenario.freqHigh || 0.3)
        );
        const p = Math.max(0, Math.min(1, rawP * (1 - freqReduction)));

        // Bernoulli draw — did event occur?
        if (Math.random() >= p) {
            losses[i] = 0;
            continue;
        }

        // Sample and sum impact categories
        let totalLoss = 0;
        IMPACT_CATS.forEach(cat => {
            const imp = scenario['impact_' + cat.id] || { low: 0, ml: 0, high: 0 };
            const lo  = imp.low  || 0;
            const ml  = imp.ml   || 0;
            const hi  = imp.high || 0;
            if (hi <= 0) return;
            const sampled = _samplePert(lo, ml, hi);
            totalLoss += Math.max(0, sampled * (1 - impactReduction));
        });
        losses[i] = totalLoss;
    }

    // Sort for percentile lookup
    losses.sort();

    const pctResults = {};
    PERCENTILES.forEach(p => {
        pctResults[p] = _percentile(losses, p);
    });

    const intervalResults = {};
    LOSS_INTERVALS.forEach(iv => {
        intervalResults[iv.label] = _percentile(losses, iv.pct);
    });

    const mean = losses.reduce((s, v) => s + v, 0) / iterations;
    const nonZero = losses.filter(v => v > 0).length;

    return {
        percentiles: pctResults,
        intervals:   intervalResults,
        mean,
        probOfLoss:  nonZero / iterations,
        freqReduction,
        impactReduction,
    };
}

// ══════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════

function fmtDollar(n, compact = false) {
    if (n == null || isNaN(n)) return '—';
    if (compact) {
        if (n >= 1e9) return '$' + (n / 1e9).toFixed(1) + 'B';
        if (n >= 1e6) return '$' + (n / 1e6).toFixed(1) + 'M';
        if (n >= 1e3) return '$' + (n / 1e3).toFixed(0) + 'K';
        return '$' + n.toFixed(0);
    }
    return '$' + n.toLocaleString('en-US', { maximumFractionDigits: 0 });
}

function fmtPct(n) {
    if (n == null || isNaN(n)) return '—';
    return (n * 100).toFixed(1) + '%';
}

function uuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = Math.random() * 16 | 0;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
}

function statusBadge(status) {
    const map = { Active: 'badge-active', Draft: 'badge-draft', 'Under Review': 'badge-review', Archived: 'badge-archived', Inactive: 'badge-inactive' };
    return `<span class="badge ${map[status] || 'badge-draft'}">${status || 'Draft'}</span>`;
}

function esc(s) {
    return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ══════════════════════════════════════════════════════════════
// Main App Class
// ══════════════════════════════════════════════════════════════

class CRQApp {
    constructor() {
        this.sb = null;
        this.user = null;
        this.data = { scenarios: [], controlObjectives: [], controls: [], settings: {} };
        this._deleteTarget = null;
        this._currentView = 'dashboard';
        this._simCache = {};
    }

    // ── Init ─────────────────────────────────────────────────
    async init() {
        this.sb = supabase.createClient(SUPABASE_URL, SUPABASE_KEY);
        const { data: { session } } = await this.sb.auth.getSession();
        if (session) {
            this.user = session.user;
            await this.loadData();
            this._showApp();
        } else {
            document.getElementById('authScreen').style.display = 'flex';
        }

        // Nav clicks
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.addEventListener('click', () => this.showView(btn.dataset.view));
        });
    }

    // ── Auth ─────────────────────────────────────────────────
    switchAuthTab(tab) {
        document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
        document.querySelector(`.auth-tab[onclick*="${tab}"]`).classList.add('active');
        document.getElementById('authBtn').textContent = tab === 'signin' ? 'Sign In' : 'Sign Up';
        this._authMode = tab;
    }

    async handleAuth() {
        const email = document.getElementById('authEmail').value.trim();
        const password = document.getElementById('authPassword').value;
        const errEl = document.getElementById('authError');
        errEl.style.display = 'none';
        const mode = this._authMode || 'signin';
        const fn = mode === 'signin'
            ? this.sb.auth.signInWithPassword({ email, password })
            : this.sb.auth.signUp({ email, password });
        const { data, error } = await fn;
        if (error) {
            errEl.textContent = error.message;
            errEl.style.display = 'block';
            return;
        }
        this.user = data.user || data.session?.user;
        if (!this.user) {
            errEl.textContent = 'Check your email for a confirmation link.';
            errEl.style.display = 'block';
            return;
        }
        await this.loadData();
        this._showApp();
    }

    async signOut() {
        await this.sb.auth.signOut();
        location.reload();
    }

    _showApp() {
        document.getElementById('authScreen').style.display = 'none';
        document.getElementById('mainApp').style.display = 'block';
        document.getElementById('userEmailDisplay').textContent = this.user.email;
        const orgName = this.data.settings.orgName || '';
        document.getElementById('orgNameDisplay').textContent = orgName;
        this.showView('dashboard');
    }

    // ── Data ─────────────────────────────────────────────────
    async loadData() {
        const { data, error } = await this.sb
            .from(TABLE)
            .select('data')
            .eq('user_id', this.user.id)
            .single();
        if (data && data.data) {
            this.data = { scenarios: [], controlObjectives: [], controls: [], settings: {}, ...data.data };
        }
    }

    async saveData() {
        this._simCache = {}; // invalidate sim cache on save
        const { error } = await this.sb
            .from(TABLE)
            .upsert({ user_id: this.user.id, data: this.data }, { onConflict: 'user_id' });
        if (error) console.error('Save error:', error);
    }

    // ── Navigation ───────────────────────────────────────────
    showView(viewName) {
        this._currentView = viewName;
        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        const section = document.getElementById(viewName);
        if (section) section.classList.add('active');
        const btn = document.querySelector(`.nav-btn[data-view="${viewName}"]`);
        if (btn) btn.classList.add('active');

        switch (viewName) {
            case 'dashboard':        this.renderDashboard(); break;
            case 'scenarios':        this.renderScenarios(); break;
            case 'controlObjectives':this.renderControlObjectives(); break;
            case 'controls':         this.renderControls(); break;
            case 'mitre':            this.renderMitreCoverage(); break;
            case 'reports':          this.renderReports(); break;
            case 'settings':         this.renderSettings(); break;
        }
    }

    // ── Dashboard ────────────────────────────────────────────
    renderDashboard() {
        const { scenarios, controlObjectives, controls } = this.data;

        // Compute portfolio exposure (sum of 90th pct residual across active scenarios)
        let portfolioP90 = 0, portfolioP50 = 0;
        const activeScenarios = scenarios.filter(s => s.status === 'Active' || !s.status);
        activeScenarios.forEach(s => {
            if (!this._simCache[s.id]) {
                this._simCache[s.id] = runMonteCarlo(s, controlObjectives, controls, 5000);
            }
            portfolioP90 += this._simCache[s.id].percentiles[90] || 0;
            portfolioP50 += this._simCache[s.id].percentiles[50] || 0;
        });

        const topRisks = [...activeScenarios]
            .map(s => ({ s, p90: (this._simCache[s.id] || {}).percentiles?.[90] || 0 }))
            .sort((a, b) => b.p90 - a.p90)
            .slice(0, 5);

        document.getElementById('dashboardContent').innerHTML = `
        <div class="dash-kpi-grid">
            <div class="kpi-card">
                <div class="kpi-label">Portfolio Exposure (90th Pct)</div>
                <div class="kpi-value">${fmtDollar(portfolioP90, true)}</div>
                <div class="kpi-sub">${activeScenarios.length} active risk event${activeScenarios.length !== 1 ? 's' : ''}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Expected Annual Loss</div>
                <div class="kpi-value">${fmtDollar(portfolioP50, true)}</div>
                <div class="kpi-sub">50th percentile</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Control Objectives</div>
                <div class="kpi-value">${controlObjectives.length}</div>
                <div class="kpi-sub">${controls.filter(c=>c.status==='Active').length} active controls</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Total Risk Events</div>
                <div class="kpi-value">${scenarios.length}</div>
                <div class="kpi-sub">${scenarios.filter(s=>s.status==='Draft').length} drafts</div>
            </div>
        </div>

        <div class="dash-grid-2">
            <div class="card">
                <div class="dash-section-title">Top Risk Events by 90th Percentile</div>
                ${topRisks.length === 0 ? `<div class="empty-state">No active scenarios</div>` : topRisks.map(({ s, p90 }) => {
                    const bar = portfolioP90 > 0 ? (p90 / portfolioP90 * 100) : 0;
                    return `<div style="margin-bottom:14px;cursor:pointer" onclick="crq.showScenarioDetail('${s.id}')">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
                            <span style="font-size:0.875rem;font-weight:600">${esc(s.name)}</span>
                            <span style="font-size:0.875rem;font-weight:700">${fmtDollar(p90, true)}</span>
                        </div>
                        <div class="risk-bar-wrap"><div class="risk-bar" style="width:${bar.toFixed(0)}%"></div></div>
                    </div>`;
                }).join('')}
            </div>

            <div class="card">
                <div class="dash-section-title">Control Coverage</div>
                ${controlObjectives.length === 0 ? `<div class="empty-state">No control objectives defined</div>` :
                controlObjectives.map(co => {
                    const eff = calcControlEffectiveness(co.id, controls);
                    const pct = Math.round(eff * 100);
                    const color = pct >= 80 ? 'var(--success)' : pct >= 50 ? 'var(--warning)' : 'var(--danger)';
                    return `<div style="margin-bottom:12px">
                        <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                            <span style="font-size:0.82rem;font-weight:500">${esc(co.name)}</span>
                            <span style="font-size:0.82rem;font-weight:700;color:${color}">${pct}%</span>
                        </div>
                        <div class="risk-bar-wrap"><div class="risk-bar" style="width:${pct}%;background:${color}"></div></div>
                    </div>`;
                }).join('')}
            </div>
        </div>

        <div class="card" style="margin-top:20px">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
                <div class="dash-section-title" style="margin:0">Most Impactful Actions</div>
                <button class="btn-secondary" style="font-size:0.78rem;padding:5px 10px" onclick="crq._runTopActions()">↻ Recompute</button>
            </div>
            <div style="font-size:0.78rem;color:var(--text-secondary);margin-bottom:14px">
                Simulated improvements — each action's estimated reduction in portfolio 90th percentile loss.
            </div>
            <div id="topActionsContent">
                <div style="text-align:center;padding:24px">
                    <div class="spinner"></div>
                    <div style="font-size:0.82rem;color:var(--text-secondary);margin-top:8px">Running what-if analysis…</div>
                </div>
            </div>
        </div>`;

        // Kick off async after DOM paints
        setTimeout(() => this._runTopActions(), 30);
    }

    _runTopActions() {
        document.getElementById('topActionsContent').innerHTML = `
            <div style="text-align:center;padding:24px">
                <div class="spinner"></div>
                <div style="font-size:0.82rem;color:var(--text-secondary);margin-top:8px">Running what-if analysis…</div>
            </div>`;
        // Yield to browser then compute
        setTimeout(() => {
            const actions = this._computeTopActions();
            const el = document.getElementById('topActionsContent');
            if (!el) return;
            if (actions.length === 0) {
                el.innerHTML = `<div class="empty-state">No active risk events or controls to analyze.</div>`;
                return;
            }
            const maxDelta = actions[0].delta;
            el.innerHTML = actions.map((a, i) => {
                const barW = maxDelta > 0 ? (a.delta / maxDelta * 100).toFixed(0) : 0;
                const dimLabel = { design: 'Design', scope: 'Scope', operating: 'Operating' }[a.dimension];
                const dimColor = { design: 'var(--primary)', scope: 'var(--warning)', operating: 'var(--success)' }[a.dimension];
                return `<div class="action-row" onclick="crq.showControlDetail('${a.controlId}')">
                    <div class="action-rank">${i + 1}</div>
                    <div class="action-body">
                        <div class="action-title">
                            <span>${esc(a.controlName)}</span>
                            <span class="action-dim-badge" style="background:${dimColor}20;color:${dimColor}">${dimLabel} ${a.currentVal}% → ${a.newVal}%</span>
                        </div>
                        <div class="action-bar-wrap">
                            <div class="action-bar" style="width:${barW}%;background:${dimColor}"></div>
                        </div>
                        <div class="action-meta">
                            Reduces portfolio P90 by approx. <strong>${fmtDollar(a.delta, true)}</strong>
                            · affects ${a.scenariosAffected} risk event${a.scenariosAffected !== 1 ? 's' : ''}
                        </div>
                    </div>
                </div>`;
            }).join('');
        }, 10);
    }

    _computeTopActions() {
        const { scenarios, controlObjectives, controls } = this.data;
        const BOOST = 20;
        const ITER  = 1000;
        const active = scenarios.filter(s => s.status === 'Active' || !s.status);
        if (active.length === 0 || controls.length === 0) return [];

        // Baseline portfolio P90
        const baseP90 = active.map(s =>
            runMonteCarlo(s, controlObjectives, controls, ITER).percentiles[90]
        );
        const totalBase = baseP90.reduce((a, b) => a + b, 0);

        const actions = [];

        controls.filter(c => c.status !== 'Inactive' && (c.linkedCOs||[]).length > 0).forEach(ctrl => {
            ['design', 'scope', 'operating'].forEach(dim => {
                const current = ctrl[dim] || 0;
                if (current >= 98) return; // already near max

                const newVal = Math.min(100, current + BOOST);
                const modCtrls = controls.map(c => c.id === ctrl.id ? { ...c, [dim]: newVal } : c);

                let totalNew = 0;
                let scenariosAffected = 0;
                active.forEach((s, i) => {
                    const newP90 = runMonteCarlo(s, controlObjectives, modCtrls, ITER).percentiles[90];
                    totalNew += newP90;
                    if (newP90 < baseP90[i] - 1000) scenariosAffected++;
                });

                const delta = totalBase - totalNew;
                if (delta > 1000) {
                    actions.push({ controlId: ctrl.id, controlName: ctrl.name, dimension: dim, currentVal: current, newVal, delta, scenariosAffected });
                }
            });
        });

        return actions.sort((a, b) => b.delta - a.delta).slice(0, 8);
    }

    // ── Risk Scenarios ───────────────────────────────────────
    renderScenarios() {
        const search = (document.getElementById('scenariosSearch')?.value || '').toLowerCase();
        const catFilter = document.getElementById('scenarioFilterCategory')?.value || '';
        const statusFilter = document.getElementById('scenarioFilterStatus')?.value || '';

        // Populate category filter
        const catSel = document.getElementById('scenarioFilterCategory');
        if (catSel && catSel.options.length <= 1) {
            RISK_CATEGORIES.forEach(c => {
                const o = document.createElement('option'); o.value = c; o.textContent = c;
                catSel.appendChild(o);
            });
        }

        let list = this.data.scenarios;
        if (search) list = list.filter(s => s.name?.toLowerCase().includes(search) || s.description?.toLowerCase().includes(search));
        if (catFilter) list = list.filter(s => s.category === catFilter);
        if (statusFilter) list = list.filter(s => s.status === statusFilter);

        const el = document.getElementById('scenariosList');
        if (list.length === 0) {
            el.innerHTML = `<div class="empty-state"><div class="empty-state-icon">⚡</div><div class="empty-state-title">No risk events found</div><p>Create your first risk event to get started.</p></div>`;
            return;
        }

        el.innerHTML = `<div class="cards-grid">${list.map(s => {
            const sim = this._simCache[s.id];
            const p90 = sim ? fmtDollar(sim.percentiles[90], true) : '—';
            const p50 = sim ? fmtDollar(sim.percentiles[50], true) : '—';
            const coCount = (s.linkedCOs || []).length;
            return `<div class="card card-clickable" onclick="crq.showScenarioDetail('${s.id}')">
                <div style="display:flex;justify-content:space-between;align-items:flex-start">
                    <div style="flex:1">
                        <div class="card-title">${esc(s.name)}</div>
                        <div class="card-meta">
                            ${statusBadge(s.status)}
                            ${s.category ? `<span class="tag">${esc(s.category)}</span>` : ''}
                        </div>
                        ${s.description ? `<div class="card-desc">${esc(s.description.slice(0, 100))}${s.description.length > 100 ? '…' : ''}</div>` : ''}
                    </div>
                    <div class="scenario-score" style="margin-left:14px">
                        <div class="scenario-score-value">${p90}</div>
                        <div class="scenario-score-label">90th pct</div>
                        <div style="font-size:0.78rem;color:var(--text-secondary);margin-top:2px">${p50} median</div>
                    </div>
                </div>
                <div style="margin-top:12px;display:flex;gap:8px;align-items:center;font-size:0.78rem;color:var(--text-secondary)">
                    <span>Freq: ${s.freqML != null ? (s.freqML*100).toFixed(0)+'% ML' : '—'}</span>
                    <span>·</span>
                    <span>${coCount} control objective${coCount !== 1 ? 's' : ''}</span>
                </div>
                <div class="card-actions">
                    <button class="btn-icon" onclick="event.stopPropagation();crq.openFullScreenForm('scenarios',crq._getScenario('${s.id}'))">✎</button>
                    <button class="btn-icon danger" onclick="event.stopPropagation();crq.openDeleteModal('scenarios','${s.id}')">✕</button>
                </div>
            </div>`;
        }).join('')}</div>`;
    }

    _getScenario(id) { return this.data.scenarios.find(s => s.id === id); }
    _getCO(id)       { return this.data.controlObjectives.find(c => c.id === id); }
    _getControl(id)  { return this.data.controls.find(c => c.id === id); }

    showScenarioDetail(id) {
        const s = this._getScenario(id);
        if (!s) return;

        const { scenarios, controlObjectives, controls } = this.data;

        // Run both inherent and residual sims
        const inherent = runMonteCarlo(s, controlObjectives, controls, 10000, true);
        const residual = runMonteCarlo(s, controlObjectives, controls, 10000, false);
        this._simCache[s.id] = residual;

        const linkedCOs = (s.linkedCOs || []).map(cid => controlObjectives.find(c => c.id === cid)).filter(Boolean);

        const tableRows = (simData, label) => PERCENTILES.map(p => {
            const val = simData.percentiles[p];
            return `<tr><td class="label">${p}th percentile</td><td class="dollar">${fmtDollar(val)}</td></tr>`;
        }).join('');

        const intervalRows = (simData) => LOSS_INTERVALS.map(iv => {
            const val = simData.intervals[iv.label];
            return `<tr><td class="label">${iv.label} years</td><td class="dollar">${fmtDollar(val)}</td></tr>`;
        }).join('');

        const reduction_freq_pct = (residual.freqReduction * 100).toFixed(0);
        const reduction_imp_pct  = (residual.impactReduction * 100).toFixed(0);

        // Impact category breakdown
        const impactRows = IMPACT_CATS.map(cat => {
            const imp = s['impact_' + cat.id] || {};
            const hasData = imp.high > 0;
            return `<tr>
                <td style="font-size:0.82rem">${cat.label}</td>
                <td class="dollar" style="font-size:0.82rem">${hasData ? fmtDollar(imp.low) : '—'}</td>
                <td class="dollar" style="font-size:0.82rem">${hasData ? fmtDollar(imp.ml)  : '—'}</td>
                <td class="dollar" style="font-size:0.82rem">${hasData ? fmtDollar(imp.high): '—'}</td>
            </tr>`;
        }).join('');

        document.getElementById('detailPageContent').innerHTML = `
        <div class="detail-header">
            <button class="btn-back" onclick="crq.showView('scenarios')">← Risk Events</button>
            <h2>${esc(s.name)}</h2>
            <div class="detail-header-actions">
                <button class="btn-sim" onclick="crq._rerunSim('${s.id}')">⟳ Re-run Simulation</button>
                <button class="btn-primary" onclick="crq.openFullScreenForm('scenarios',crq._getScenario('${s.id}'))">Edit</button>
                <button class="btn-icon danger" onclick="crq.openDeleteModal('scenarios','${s.id}')">✕</button>
            </div>
        </div>

        <div class="detail-layout">
            <div class="detail-main">

                <!-- Simulation Output -->
                <div class="detail-card">
                    <div class="detail-card-title">Quantification Results — 10,000 Iterations</div>
                    <div style="display:flex;gap:14px;margin-bottom:12px;font-size:0.8rem;color:var(--text-secondary)">
                        <span>Freq. Reduction: <strong style="color:var(--success)">${reduction_freq_pct}%</strong></span>
                        <span>Impact Reduction: <strong style="color:var(--success)">${reduction_imp_pct}%</strong></span>
                        <span>Prob. of Loss: <strong>${fmtPct(residual.probOfLoss)}</strong></span>
                        <span>Mean: <strong>${fmtDollar(residual.mean, true)}</strong></span>
                    </div>
                    <div class="quant-pair">
                        <div class="quant-section">
                            <div class="quant-section-header">
                                <span class="quant-section-title">Percentile Output</span>
                            </div>
                            <table class="quant-table">
                                <thead><tr><th>Metric</th><th>Inherent</th><th>Residual</th><th>Reduction</th></tr></thead>
                                <tbody>
                                ${PERCENTILES.map(p => {
                                    const inh = inherent.percentiles[p];
                                    const res = residual.percentiles[p];
                                    const redAmt = inh > 0 ? ((1 - res/inh)*100).toFixed(0) + '%' : '—';
                                    return `<tr>
                                        <td class="label">${p}th pct</td>
                                        <td class="dollar">${fmtDollar(inh, true)}</td>
                                        <td class="dollar">${fmtDollar(res, true)}</td>
                                        <td class="reduction-cell">${inh > 0 ? redAmt : '—'}</td>
                                    </tr>`;
                                }).join('')}
                                </tbody>
                            </table>
                        </div>
                        <div class="quant-section">
                            <div class="quant-section-header">
                                <span class="quant-section-title">Return Period Output</span>
                            </div>
                            <table class="quant-table">
                                <thead><tr><th>Return Period</th><th>Inherent</th><th>Residual</th><th>Reduction</th></tr></thead>
                                <tbody>
                                ${LOSS_INTERVALS.map(iv => {
                                    const inh = inherent.intervals[iv.label];
                                    const res = residual.intervals[iv.label];
                                    const redAmt = inh > 0 ? ((1 - res/inh)*100).toFixed(0) + '%' : '—';
                                    return `<tr>
                                        <td class="label">${iv.label} years</td>
                                        <td class="dollar">${fmtDollar(inh, true)}</td>
                                        <td class="dollar">${fmtDollar(res, true)}</td>
                                        <td class="reduction-cell">${inh > 0 ? redAmt : '—'}</td>
                                    </tr>`;
                                }).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Impact Categories -->
                <div class="detail-card">
                    <div class="detail-card-title">Impact Category Estimates</div>
                    <table class="quant-table">
                        <thead><tr><th>Category</th><th>Low</th><th>Most Likely</th><th>High</th></tr></thead>
                        <tbody>${impactRows}</tbody>
                    </table>
                </div>

                <!-- Linked Control Objectives -->
                <div class="detail-card">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
                        <div class="detail-card-title" style="margin-bottom:0">Linked Control Objectives</div>
                        <button class="btn-primary" style="font-size:0.8rem;padding:6px 12px" onclick="crq.openLinkCOsModal('${s.id}')">+ Link CO</button>
                    </div>
                    ${linkedCOs.length === 0 ? `<div class="empty-state">No control objectives linked</div>` :
                    `<div class="linked-list">${linkedCOs.map(co => {
                        const eff = calcControlEffectiveness(co.id, controls);
                        const freqRed = ((co.maxFreqReduction || 0) * eff).toFixed(1);
                        const impRed  = ((co.maxImpactReduction || 0) * eff).toFixed(1);
                        return `<div class="linked-item">
                            <div>
                                <div class="linked-item-name" style="cursor:pointer" onclick="crq.showCODetail('${co.id}')">${esc(co.name)}</div>
                                <div class="linked-item-meta">Achievement: ${(eff*100).toFixed(0)}% · Freq ↓${freqRed}% · Impact ↓${impRed}%</div>
                            </div>
                            <div class="linked-item-actions">
                                <button class="btn-icon danger" title="Unlink" onclick="crq.unlinkCOFromScenario('${s.id}','${co.id}')">✕</button>
                            </div>
                        </div>`;
                    }).join('')}</div>`}
                </div>

            </div>
            <div class="detail-sidebar">
                <!-- Details -->
                <div class="detail-card">
                    <div class="detail-card-title">Details</div>
                    <div class="field-row"><div class="field-label">Status</div><div>${statusBadge(s.status)}</div></div>
                    <div class="field-row"><div class="field-label">Category</div><div>${s.category ? `<span class="tag">${esc(s.category)}</span>` : '—'}</div></div>
                    <div class="field-row"><div class="field-label">Description</div><div class="field-value">${esc(s.description || '') || '—'}</div></div>
                    <div class="field-row"><div class="field-label">Created</div><div class="field-value" style="font-size:0.8rem;color:var(--text-secondary)">${s.createdAt ? new Date(s.createdAt).toLocaleDateString() : '—'}</div></div>
                </div>
                <!-- Frequency -->
                <div class="detail-card">
                    <div class="detail-card-title">Frequency (Annual Prob.)</div>
                    <div class="field-row"><div class="field-label">Low</div><div class="field-value">${s.freqLow != null ? (s.freqLow*100).toFixed(1)+'%' : '—'}</div></div>
                    <div class="field-row"><div class="field-label">Most Likely</div><div class="field-value">${s.freqML != null ? (s.freqML*100).toFixed(1)+'%' : '—'}</div></div>
                    <div class="field-row"><div class="field-label">High</div><div class="field-value">${s.freqHigh != null ? (s.freqHigh*100).toFixed(1)+'%' : '—'}</div></div>
                </div>
                <!-- MITRE Techniques -->
                <div class="detail-card">
                    <div class="detail-card-title">MITRE ATT&amp;CK Techniques</div>
                    ${(s.mitreTechniques || []).length === 0 ? '<div style="font-size:0.82rem;color:var(--text-secondary)">None linked</div>' :
                    `<div style="display:flex;flex-wrap:wrap;gap:4px">${(s.mitreTechniques||[]).map(tid => {
                        const t = MITRE_TECHNIQUES.find(x => x.id === tid);
                        return t ? `<span class="mitre-technique scenario" title="${t.id}">${esc(t.name)}</span>` : '';
                    }).join('')}</div>`}
                </div>
            </div>
        </div>`;

        this._switchDetailView();
    }

    _rerunSim(id) {
        delete this._simCache[id];
        this.showScenarioDetail(id);
    }

    // ── Control Objectives ───────────────────────────────────
    renderControlObjectives() {
        const list = this.data.controlObjectives;
        const el = document.getElementById('controlObjectivesList');
        if (list.length === 0) {
            el.innerHTML = `<div class="empty-state"><div class="empty-state-icon">🎯</div><div class="empty-state-title">No control objectives</div><p>Define what your controls must achieve.</p></div>`;
            return;
        }
        el.innerHTML = `<div class="cards-grid">${list.map(co => {
            const eff = calcControlEffectiveness(co.id, this.data.controls);
            const pct = Math.round(eff * 100);
            const ctrlCount = this.data.controls.filter(c => (c.linkedCOs||[]).includes(co.id)).length;
            return `<div class="card card-clickable" onclick="crq.showCODetail('${co.id}')">
                <div class="card-title">${esc(co.name)}</div>
                <div class="card-desc">${esc((co.description||'').slice(0,100))}${(co.description||'').length>100?'…':''}</div>
                <div style="margin:12px 0">
                    <div style="display:flex;justify-content:space-between;font-size:0.78rem;margin-bottom:4px">
                        <span style="color:var(--text-secondary)">CO Achievement</span>
                        <span style="font-weight:700;color:${pct>=80?'var(--success)':pct>=50?'var(--warning)':'var(--danger)'}">${pct}%</span>
                    </div>
                    <div class="risk-bar-wrap"><div class="risk-bar" style="width:${pct}%;background:${pct>=80?'var(--success)':pct>=50?'var(--warning)':'var(--danger)'}"></div></div>
                </div>
                <div style="font-size:0.78rem;color:var(--text-secondary);display:flex;gap:10px">
                    <span>Freq ↓${co.maxFreqReduction||0}% max</span>
                    <span>·</span>
                    <span>Impact ↓${co.maxImpactReduction||0}% max</span>
                    <span>·</span>
                    <span>${ctrlCount} control${ctrlCount!==1?'s':''}</span>
                </div>
                <div class="card-actions">
                    <button class="btn-icon" onclick="event.stopPropagation();crq.openFullScreenForm('controlObjectives',crq._getCO('${co.id}'))">✎</button>
                    <button class="btn-icon danger" onclick="event.stopPropagation();crq.openDeleteModal('controlObjectives','${co.id}')">✕</button>
                </div>
            </div>`;
        }).join('')}</div>`;
    }

    showCODetail(id) {
        const co = this._getCO(id);
        if (!co) return;
        const { controls, scenarios } = this.data;
        const linkedControls = controls.filter(c => (c.linkedCOs||[]).includes(co.id));
        const linkedScenarios = scenarios.filter(s => (s.linkedCOs||[]).includes(co.id));
        const eff = calcControlEffectiveness(co.id, controls);

        document.getElementById('detailPageContent').innerHTML = `
        <div class="detail-header">
            <button class="btn-back" onclick="crq.showView('controlObjectives')">← Back</button>
            <h2>${esc(co.name)}</h2>
            <div class="detail-header-actions">
                <button class="btn-primary" onclick="crq.openFullScreenForm('controlObjectives',crq._getCO('${co.id}'))">Edit</button>
                <button class="btn-icon danger" onclick="crq.openDeleteModal('controlObjectives','${co.id}')">✕</button>
            </div>
        </div>
        <div class="detail-layout">
            <div class="detail-main">
                <!-- Achievement -->
                <div class="detail-card">
                    <div class="detail-card-title">CO Achievement</div>
                    <div class="co-achievement">
                        <div class="co-achievement-pct">${(eff*100).toFixed(0)}%</div>
                        <div>
                            <div class="co-achievement-label">Current achievement via linked controls</div>
                            <div style="font-size:0.78rem;color:var(--text-secondary);margin-top:2px">
                                Effective Freq Reduction: <strong>${((co.maxFreqReduction||0)*eff).toFixed(1)}%</strong> ·
                                Effective Impact Reduction: <strong>${((co.maxImpactReduction||0)*eff).toFixed(1)}%</strong>
                            </div>
                        </div>
                    </div>
                    <div class="effectiveness-bar-wrap" style="margin-top:10px">
                        <div class="effectiveness-bar-track"><div class="effectiveness-bar-fill" style="width:${(eff*100).toFixed(0)}%"></div></div>
                        <div class="effectiveness-pct">${(eff*100).toFixed(0)}%</div>
                    </div>
                </div>
                <!-- Controls -->
                <div class="detail-card">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
                        <div class="detail-card-title" style="margin-bottom:0">Controls Contributing to this Objective</div>
                        <button class="btn-primary" style="font-size:0.8rem;padding:6px 12px" onclick="crq.openLinkControlsModal('${co.id}')">+ Link Control</button>
                    </div>
                    ${linkedControls.length === 0 ? `<div class="empty-state">No controls linked</div>` :
                    `<div class="linked-list">${linkedControls.map(c => {
                        const cEff = (c.design||0)/100 * (c.scope||0)/100 * (c.operating||0)/100;
                        return `<div class="linked-item">
                            <div>
                                <div class="linked-item-name" style="cursor:pointer" onclick="crq.showControlDetail('${c.id}')">${esc(c.name)}</div>
                                <div class="linked-item-meta">
                                    Design ${c.design||0}% · Scope ${c.scope||0}% · Operating ${c.operating||0}% = Effectiveness ${(cEff*100).toFixed(1)}%
                                </div>
                            </div>
                            <div class="linked-item-actions">
                                ${statusBadge(c.status)}
                                <button class="btn-icon danger" onclick="crq.unlinkControlFromCO('${c.id}','${co.id}')">✕</button>
                            </div>
                        </div>`;
                    }).join('')}</div>`}
                </div>
                <!-- Scenarios -->
                <div class="detail-card">
                    <div class="detail-card-title">Risk Events Using This Objective</div>
                    ${linkedScenarios.length === 0 ? `<div class="empty-state">No scenarios linked</div>` :
                    `<div class="linked-list">${linkedScenarios.map(s =>
                        `<div class="linked-item">
                            <div class="linked-item-name" style="cursor:pointer" onclick="crq.showScenarioDetail('${s.id}')">${esc(s.name)}</div>
                            ${statusBadge(s.status)}
                        </div>`
                    ).join('')}</div>`}
                </div>
            </div>
            <div class="detail-sidebar">
                <div class="detail-card">
                    <div class="detail-card-title">Details</div>
                    <div class="field-row"><div class="field-label">Max Freq. Reduction</div><div class="field-value">${co.maxFreqReduction||0}%</div></div>
                    <div class="field-row"><div class="field-label">Max Impact Reduction</div><div class="field-value">${co.maxImpactReduction||0}%</div></div>
                    <div class="field-row"><div class="field-label">Description</div><div class="field-value">${esc(co.description||'') || '—'}</div></div>
                </div>
                <div class="detail-card">
                    <div class="detail-card-title">MITRE Mitigations</div>
                    ${(co.mitreMitigations||[]).length === 0 ? '<div style="font-size:0.82rem;color:var(--text-secondary)">None linked</div>' :
                    `<div style="display:flex;flex-wrap:wrap;gap:4px">${(co.mitreMitigations||[]).map(mid => {
                        const m = MITRE_MITIGATIONS.find(x => x.id === mid);
                        return m ? `<span class="tag">${esc(m.name)}</span>` : '';
                    }).join('')}</div>`}
                </div>
            </div>
        </div>`;
        this._switchDetailView();
    }

    // ── Controls ─────────────────────────────────────────────
    renderControls() {
        const search  = (document.getElementById('controlsSearch')?.value || '').toLowerCase();
        const sFilt   = document.getElementById('controlFilterStatus')?.value || '';
        let list = this.data.controls;
        if (search) list = list.filter(c => c.name?.toLowerCase().includes(search) || c.description?.toLowerCase().includes(search));
        if (sFilt) list = list.filter(c => c.status === sFilt);

        const el = document.getElementById('controlsList');
        if (list.length === 0) {
            el.innerHTML = `<div class="empty-state"><div class="empty-state-icon">🛡️</div><div class="empty-state-title">No controls found</div><p>Add controls to contribute to your control objectives.</p></div>`;
            return;
        }
        el.innerHTML = `<div class="cards-grid">${list.map(c => {
            const eff = (c.design||0)/100 * (c.scope||0)/100 * (c.operating||0)/100;
            const pct = Math.round(eff * 100);
            const coNames = (c.linkedCOs||[]).map(id => this._getCO(id)?.name).filter(Boolean);
            return `<div class="card card-clickable" onclick="crq.showControlDetail('${c.id}')">
                <div style="display:flex;justify-content:space-between;align-items:flex-start">
                    <div class="card-title">${esc(c.name)}</div>
                    ${statusBadge(c.status)}
                </div>
                ${c.description ? `<div class="card-desc">${esc(c.description.slice(0,90))}${c.description.length>90?'…':''}</div>` : ''}
                <div style="margin:12px 0">
                    <div style="display:flex;justify-content:space-between;font-size:0.78rem;margin-bottom:4px">
                        <span style="color:var(--text-secondary)">Overall Effectiveness</span>
                        <span style="font-weight:700;color:${pct>=80?'var(--success)':pct>=50?'var(--warning)':'var(--danger)'}">${pct}%</span>
                    </div>
                    <div class="risk-bar-wrap"><div class="risk-bar" style="width:${pct}%;background:${pct>=80?'var(--success)':pct>=50?'var(--warning)':'var(--danger)'}"></div></div>
                    <div style="display:flex;gap:8px;font-size:0.72rem;color:var(--text-secondary);margin-top:4px">
                        <span>Design ${c.design||0}%</span><span>·</span>
                        <span>Scope ${c.scope||0}%</span><span>·</span>
                        <span>Operating ${c.operating||0}%</span>
                    </div>
                </div>
                ${coNames.length > 0 ? `<div style="font-size:0.78rem;color:var(--text-secondary)">COs: ${coNames.map(n=>`<span class="tag" style="font-size:0.72rem">${esc(n)}</span>`).join(' ')}</div>` : ''}
                <div class="card-actions">
                    <button class="btn-icon" onclick="event.stopPropagation();crq.openFullScreenForm('controls',crq._getControl('${c.id}'))">✎</button>
                    <button class="btn-icon danger" onclick="event.stopPropagation();crq.openDeleteModal('controls','${c.id}')">✕</button>
                </div>
            </div>`;
        }).join('')}</div>`;
    }

    showControlDetail(id) {
        const c = this._getControl(id);
        if (!c) return;
        const { controlObjectives } = this.data;
        const linkedCOs = (c.linkedCOs||[]).map(cid => controlObjectives.find(x => x.id === cid)).filter(Boolean);
        const eff = (c.design||0)/100 * (c.scope||0)/100 * (c.operating||0)/100;

        const ratings = [
            { label: 'Design', val: c.design||0, desc: 'Degree to which design achieves the control objective if fully effective' },
            { label: 'Scope', val: c.scope||0, desc: 'Percentage of the environment/assets covered by this control' },
            { label: 'Operating', val: c.operating||0, desc: 'How consistently and effectively the control operates within its scope' },
        ];

        document.getElementById('detailPageContent').innerHTML = `
        <div class="detail-header">
            <button class="btn-back" onclick="crq.showView('controls')">← Back</button>
            <h2>${esc(c.name)}</h2>
            <div class="detail-header-actions">
                <button class="btn-primary" onclick="crq.openFullScreenForm('controls',crq._getControl('${c.id}'))">Edit</button>
                <button class="btn-icon danger" onclick="crq.openDeleteModal('controls','${c.id}')">✕</button>
            </div>
        </div>
        <div class="detail-layout">
            <div class="detail-main">
                <!-- Effectiveness -->
                <div class="detail-card">
                    <div class="detail-card-title">Control Effectiveness</div>
                    <div style="display:flex;align-items:center;gap:20px;margin-bottom:16px">
                        <div style="font-size:2.5rem;font-weight:800;letter-spacing:-0.04em;color:var(--primary)">${(eff*100).toFixed(1)}%</div>
                        <div style="font-size:0.85rem;color:var(--text-secondary)">
                            Design × Scope × Operating<br>
                            <code style="font-size:0.82rem">${c.design||0}% × ${c.scope||0}% × ${c.operating||0}%</code>
                        </div>
                    </div>
                    ${ratings.map(r => `
                    <div style="margin-bottom:14px">
                        <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                            <span style="font-size:0.85rem;font-weight:600">${r.label}</span>
                            <span style="font-size:0.85rem;font-weight:700">${r.val}%</span>
                        </div>
                        <div class="effectiveness-bar-wrap">
                            <div class="effectiveness-bar-track"><div class="effectiveness-bar-fill" style="width:${r.val}%"></div></div>
                        </div>
                        <div style="font-size:0.75rem;color:var(--text-tertiary);margin-top:2px">${r.desc}</div>
                    </div>`).join('')}
                </div>
                <!-- COs -->
                <div class="detail-card">
                    <div class="detail-card-title">Control Objectives Supported</div>
                    ${linkedCOs.length === 0 ? `<div class="empty-state">Not linked to any control objectives</div>` :
                    `<div class="linked-list">${linkedCOs.map(co => {
                        const coEff = calcControlEffectiveness(co.id, this.data.controls);
                        return `<div class="linked-item">
                            <div>
                                <div class="linked-item-name" style="cursor:pointer" onclick="crq.showCODetail('${co.id}')">${esc(co.name)}</div>
                                <div class="linked-item-meta">CO achievement: ${(coEff*100).toFixed(0)}% · Freq ↓${((co.maxFreqReduction||0)*coEff).toFixed(1)}% · Impact ↓${((co.maxImpactReduction||0)*coEff).toFixed(1)}%</div>
                            </div>
                            <button class="btn-icon danger" onclick="crq.unlinkControlFromCO('${c.id}','${co.id}')">✕</button>
                        </div>`;
                    }).join('')}</div>`}
                </div>
            </div>
            <div class="detail-sidebar">
                <div class="detail-card">
                    <div class="detail-card-title">Details</div>
                    <div class="field-row"><div class="field-label">Status</div><div>${statusBadge(c.status)}</div></div>
                    <div class="field-row"><div class="field-label">Description</div><div class="field-value">${esc(c.description||'') || '—'}</div></div>
                    <div class="field-row"><div class="field-label">Owner</div><div class="field-value">${esc(c.owner||'') || '—'}</div></div>
                    <div class="field-row"><div class="field-label">Review Date</div><div class="field-value">${c.reviewDate || '—'}</div></div>
                </div>
                <div class="detail-card">
                    <div class="detail-card-title">MITRE Techniques Addressed</div>
                    ${(c.mitreTechniques||[]).length === 0 ? '<div style="font-size:0.82rem;color:var(--text-secondary)">None linked</div>' :
                    `<div style="display:flex;flex-wrap:wrap;gap:4px">${(c.mitreTechniques||[]).map(tid => {
                        const t = MITRE_TECHNIQUES.find(x => x.id === tid);
                        return t ? `<span class="mitre-technique covered" title="${t.id}">${esc(t.name)}</span>` : '';
                    }).join('')}</div>`}
                </div>
            </div>
        </div>`;
        this._switchDetailView();
    }

    _switchDetailView() {
        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
        document.getElementById('detailPageView').classList.add('active');
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    }

    // ── Link / Unlink helpers ────────────────────────────────
    openLinkCOsModal(scenarioId) {
        const s = this._getScenario(scenarioId);
        if (!s) return;
        const available = this.data.controlObjectives.filter(co => !(s.linkedCOs||[]).includes(co.id));
        this._openLinkModal('Link Control Objectives', available,
            (id) => `${this._getCO(id)?.name || id}`,
            (selected) => {
                s.linkedCOs = [...(s.linkedCOs||[]), ...selected];
                this._simCache = {};
                this.saveData().then(() => this.showScenarioDetail(scenarioId));
            }
        );
    }

    openLinkControlsModal(coId) {
        const available = this.data.controls.filter(c => !(c.linkedCOs||[]).includes(coId));
        this._openLinkModal('Link Controls', available,
            (id) => { const c = this._getControl(id); return c ? `${c.name} (${c.design||0}%D × ${c.scope||0}%S × ${c.operating||0}%O)` : id; },
            (selected) => {
                selected.forEach(cid => {
                    const ctrl = this._getControl(cid);
                    if (ctrl) ctrl.linkedCOs = [...(ctrl.linkedCOs||[]), coId];
                });
                this._simCache = {};
                this.saveData().then(() => this.showCODetail(coId));
            }
        );
    }

    _openLinkModal(title, items, descFn, onConfirm) {
        const modalEl = document.getElementById('deleteModal');
        modalEl.className = 'modal-overlay open';
        modalEl.innerHTML = `
        <div class="modal-card link-modal">
            <h3>${esc(title)}</h3>
            <input type="text" class="form-input link-search" id="linkSearchInput" placeholder="Search…" oninput="crq._filterLinkList()">
            <div class="link-list" id="linkList" style="margin:10px 0">
                ${items.length === 0 ? '<div style="padding:16px;text-align:center;color:var(--text-secondary);font-size:0.875rem">All items already linked</div>' :
                items.map(item => `
                <label class="link-item-row">
                    <input type="checkbox" class="link-checkbox" value="${item.id}">
                    <div>
                        <div class="link-item-title">${esc(item.name)}</div>
                        ${item.description ? `<div class="link-item-meta">${esc(item.description.slice(0,80))}</div>` : ''}
                    </div>
                </label>`).join('')}
            </div>
            <div class="modal-actions">
                <button class="btn-secondary" onclick="crq.closeDeleteModal()">Cancel</button>
                <button class="btn-primary" onclick="crq._confirmLink()">Link Selected</button>
            </div>
        </div>`;
        this._pendingLinkConfirm = onConfirm;
    }

    _filterLinkList() {
        const q = document.getElementById('linkSearchInput')?.value?.toLowerCase() || '';
        document.querySelectorAll('.link-item-row').forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(q) ? '' : 'none';
        });
    }

    _confirmLink() {
        const selected = Array.from(document.querySelectorAll('.link-checkbox:checked')).map(cb => cb.value);
        if (this._pendingLinkConfirm) this._pendingLinkConfirm(selected);
        this.closeDeleteModal();
    }

    unlinkCOFromScenario(scenarioId, coId) {
        if (!confirm('Remove this control objective from the risk event?')) return;
        const s = this._getScenario(scenarioId);
        if (s) s.linkedCOs = (s.linkedCOs||[]).filter(id => id !== coId);
        this._simCache = {};
        this.saveData().then(() => this.showScenarioDetail(scenarioId));
    }

    unlinkControlFromCO(controlId, coId) {
        if (!confirm('Remove this control from the objective?')) return;
        const c = this._getControl(controlId);
        if (c) c.linkedCOs = (c.linkedCOs||[]).filter(id => id !== coId);
        this._simCache = {};
        this.saveData().then(() => this.showCODetail(coId));
    }

    // ── MITRE Coverage ───────────────────────────────────────
    renderMitreCoverage() {
        const { scenarios, controls } = this.data;

        // Collect covered IDs from active controls (techniques + sub-techniques)
        const controlCoverage = new Set();
        controls.filter(c => c.status !== 'Inactive').forEach(c => {
            (c.mitreTechniques||[]).forEach(t => controlCoverage.add(t));
        });

        // Collect in-scope IDs from risk events
        const scenarioTechniques = new Set();
        scenarios.forEach(s => (s.mitreTechniques||[]).forEach(t => scenarioTechniques.add(t)));

        // Helper: get coverage class for any ID
        const getClass = (id) => {
            const inCtrl = controlCoverage.has(id);
            const inScen = scenarioTechniques.has(id);
            if (inCtrl && inScen) return 'mn-covered';
            if (inCtrl)           return 'mn-ctrl-only';
            if (inScen)           return 'mn-gap';
            return 'mn-none';
        };

        // Compute summary stats (techniques + sub-techniques combined)
        const allInScope   = [...scenarioTechniques];
        const allCovered   = allInScope.filter(id => controlCoverage.has(id));
        const coverPct     = allInScope.length > 0 ? Math.round(allCovered.length / allInScope.length * 100) : 0;

        document.getElementById('mitreCoverageContent').innerHTML = `
        <div style="display:flex;gap:16px;margin-bottom:20px;flex-wrap:wrap">
            <div class="kpi-card" style="min-width:160px">
                <div class="kpi-label">In Threat Profile</div>
                <div class="kpi-value">${allInScope.length}</div>
                <div class="kpi-sub">techniques / sub-techniques</div>
            </div>
            <div class="kpi-card" style="min-width:160px">
                <div class="kpi-label">Covered by Controls</div>
                <div class="kpi-value" style="color:var(--success)">${allCovered.length}</div>
            </div>
            <div class="kpi-card" style="min-width:160px">
                <div class="kpi-label">Coverage Rate</div>
                <div class="kpi-value">${coverPct}%</div>
            </div>
            <div class="kpi-card" style="min-width:160px">
                <div class="kpi-label">Gaps</div>
                <div class="kpi-value" style="color:var(--danger)">${allInScope.length - allCovered.length}</div>
            </div>
        </div>

        <div class="mitre-legend">
            <div class="mitre-legend-item"><div class="mitre-legend-dot mn-covered"></div> Covered (in profile + controlled)</div>
            <div class="mitre-legend-item"><div class="mitre-legend-dot mn-gap"></div> Gap (in profile, not controlled)</div>
            <div class="mitre-legend-item"><div class="mitre-legend-dot mn-ctrl-only"></div> Controlled (not in current profile)</div>
            <div class="mitre-legend-item"><div class="mitre-legend-dot mn-none"></div> Out of scope</div>
        </div>

        <div class="mitre-nav">
            ${MITRE_TACTICS.map(tactic => {
                const techs = MITRE_TECHNIQUES.filter(t => t.tactic === tactic.id);
                return `<div class="mn-col">
                    <div class="mn-tactic-header">${tactic.name}</div>
                    ${techs.map(tech => {
                        const subs = MITRE_SUBTECHNIQUES.filter(s => s.parentId === tech.id);
                        const techClass = getClass(tech.id);
                        // If parent isn't explicitly tagged but any sub is in scope, give parent a softer highlight
                        const anySubInScope = subs.some(s => scenarioTechniques.has(s.id));
                        const anySubCovered = subs.some(s => controlCoverage.has(s.id));
                        const parentDisplay = techClass !== 'mn-none' ? techClass
                            : anySubInScope && anySubCovered ? 'mn-covered mn-via-sub'
                            : anySubInScope ? 'mn-gap mn-via-sub'
                            : anySubCovered ? 'mn-ctrl-only mn-via-sub'
                            : 'mn-none';
                        const techClick = (parentDisplay.includes('mn-gap') || parentDisplay === 'mn-gap')
                            ? `onclick="crq.showTechGapModal('${tech.id}')" style="cursor:pointer"` : '';
                        const subsHtml = subs.length > 0 ? `
                            <div class="mn-subtechs">
                                ${subs.map(s => {
                                    const sc = getClass(s.id);
                                    const sc2 = sc === 'mn-gap' ? `onclick="crq.showTechGapModal('${s.id}')" style="cursor:pointer"` : '';
                                    return `<div class="mn-subtech ${sc}" title="${s.id}" ${sc2}>${esc(s.name)}</div>`;
                                }).join('')}
                            </div>` : '';
                        return `<div class="mn-tech ${parentDisplay}" ${techClick}>
                            <div class="mn-tech-name" title="${tech.id}">${esc(tech.name)}</div>
                            ${subsHtml}
                        </div>`;
                    }).join('')}
                </div>`;
            }).join('')}
        </div>`;
    }

    // ── MITRE Gap Modal ──────────────────────────────────────
    showTechGapModal(techId) {
        const tech = MITRE_TECHNIQUES.find(t => t.id === techId)
                  || MITRE_SUBTECHNIQUES.find(t => t.id === techId);
        if (!tech) return;

        const tactic = MITRE_TACTICS.find(t => t.id === tech.tactic)
                    || (tech.parentId ? MITRE_TACTICS.find(t => {
                        const parent = MITRE_TECHNIQUES.find(x => x.id === tech.parentId);
                        return parent && t.id === parent.tactic;
                    }) : null);

        const { scenarios, controls, controlObjectives } = this.data;

        // Risk events that include this technique
        const inEvents = scenarios.filter(s => (s.mitreTechniques||[]).includes(techId));

        // Controls that already address this (shouldn't be many since it's a gap)
        const addressing = controls.filter(c => (c.mitreTechniques||[]).includes(techId) && c.status !== 'Inactive');

        // Controls that could be extended (address related techniques in same tactic)
        const sameTacticTechs = tactic
            ? MITRE_TECHNIQUES.filter(t => t.tactic === tactic.id).map(t => t.id)
            : [];
        const extendable = controls.filter(c =>
            !addressing.includes(c) &&
            c.status !== 'Inactive' &&
            (c.mitreTechniques||[]).some(t => sameTacticTechs.includes(t))
        );

        // Suggested mitigations
        const suggMitIds = TECH_MITIGATIONS_MAP[techId] || TECH_MITIGATIONS_MAP[tech.parentId] || [];
        const suggMits = suggMitIds.map(id => MITRE_MITIGATIONS.find(m => m.id === id)).filter(Boolean);

        // COs that already address these mitigations
        const relevantCOs = controlObjectives.filter(co =>
            (co.mitreMitigations||[]).some(m => suggMitIds.includes(m))
        );

        const mitreUrl = `https://attack.mitre.org/techniques/${techId.replace('.','/')}/`;

        const el = document.getElementById('deleteModal');
        el.className = 'modal-overlay open';
        el.innerHTML = `
        <div class="modal-card" style="max-width:560px;width:92%">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px">
                <div>
                    <div style="font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:0.06em;color:var(--danger);margin-bottom:4px">
                        Coverage Gap · ${esc(tactic?.name || '')}
                    </div>
                    <h3 style="font-size:1.1rem;margin:0">${esc(tech.name)}</h3>
                    <a href="${mitreUrl}" target="_blank" style="font-size:0.78rem;color:var(--primary)">${techId} ↗</a>
                </div>
                <button class="btn-icon" onclick="crq.closeDeleteModal()" style="flex-shrink:0">✕</button>
            </div>

            ${inEvents.length > 0 ? `
            <div class="gap-modal-section">
                <div class="gap-modal-label">Appears in ${inEvents.length} Risk Event${inEvents.length>1?'s':''}</div>
                ${inEvents.map(s => `<div class="gap-modal-item">
                    <span style="font-size:0.85rem;font-weight:500">${esc(s.name)}</span>
                    ${statusBadge(s.status)}
                </div>`).join('')}
            </div>` : ''}

            <div class="gap-modal-section">
                <div class="gap-modal-label">Recommended MITRE Mitigations</div>
                ${suggMits.length === 0 ? `<div style="font-size:0.82rem;color:var(--text-secondary)">No specific mitigations mapped</div>` :
                suggMits.map(m => {
                    const hasCO = controlObjectives.some(co => (co.mitreMitigations||[]).includes(m.id));
                    return `<div class="gap-modal-item">
                        <div>
                            <span style="font-size:0.85rem;font-weight:500">${esc(m.name)}</span>
                            <span style="font-size:0.72rem;color:var(--text-tertiary);margin-left:4px">${m.id}</span>
                        </div>
                        ${hasCO ? `<span style="font-size:0.72rem;color:var(--success);font-weight:600">CO exists ✓</span>`
                                 : `<span style="font-size:0.72rem;color:var(--warning);font-weight:600">No CO</span>`}
                    </div>`;
                }).join('')}
            </div>

            ${relevantCOs.length > 0 ? `
            <div class="gap-modal-section">
                <div class="gap-modal-label">Existing Control Objectives to Extend</div>
                ${relevantCOs.map(co => {
                    const eff = calcControlEffectiveness(co.id, controls);
                    return `<div class="gap-modal-item">
                        <span style="font-size:0.85rem;font-weight:500;cursor:pointer" onclick="crq.closeDeleteModal();crq.showCODetail('${co.id}')">${esc(co.name)}</span>
                        <span style="font-size:0.78rem;color:var(--text-secondary)">${(eff*100).toFixed(0)}% achieved</span>
                    </div>`;
                }).join('')}
            </div>` : ''}

            ${extendable.length > 0 ? `
            <div class="gap-modal-section">
                <div class="gap-modal-label">Controls That Could Cover This Technique</div>
                ${extendable.slice(0,4).map(c => {
                    const eff = (c.design||0)/100*(c.scope||0)/100*(c.operating||0)/100;
                    return `<div class="gap-modal-item">
                        <span style="font-size:0.85rem;font-weight:500;cursor:pointer" onclick="crq.closeDeleteModal();crq.showControlDetail('${c.id}')">${esc(c.name)}</span>
                        <span style="font-size:0.78rem;color:var(--text-secondary)">${(eff*100).toFixed(0)}% effective</span>
                    </div>`;
                }).join('')}
            </div>` : ''}

            <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">
                <button class="btn-secondary" onclick="crq.closeDeleteModal()">Close</button>
                <button class="btn-primary" onclick="crq.closeDeleteModal();crq.openFullScreenForm('controlObjectives',null)">+ New Control Objective</button>
            </div>
        </div>`;
    }

    // ── Reports ──────────────────────────────────────────────
    renderReports() {
        document.getElementById('reportsContent').innerHTML = `
        <div class="section-header">
            <div><h2>Reports</h2><p class="section-description">Export and analyze your cyber risk data.</p></div>
        </div>
        <div class="cards-grid-3">
            <div class="card report-card" onclick="crq.exportScenarioSummary()">
                <div class="report-icon">📊</div>
                <div class="report-title">Risk Event Summary CSV</div>
                <div class="report-desc">Export all scenarios with inherent and residual risk at key percentiles.</div>
            </div>
            <div class="card report-card" onclick="crq.exportControlsCSV()">
                <div class="report-icon">🛡️</div>
                <div class="report-title">Controls Effectiveness CSV</div>
                <div class="report-desc">Export all controls with design, scope, operating scores and overall effectiveness.</div>
            </div>
            <div class="card report-card" onclick="crq.exportPortfolioJSON()">
                <div class="report-icon">📁</div>
                <div class="report-title">Full Portfolio Export (JSON)</div>
                <div class="report-desc">Complete data export including all scenarios, COs, and controls for backup or import.</div>
            </div>
        </div>`;
    }

    exportScenarioSummary() {
        const { scenarios, controlObjectives, controls } = this.data;
        const header = ['Name','Category','Status','Freq Low%','Freq ML%','Freq High%','Freq Reduction%','Impact Reduction%','Inherent P50','Inherent P90','Inherent P99','Residual P50','Residual P90','Residual P99'];
        const rows = scenarios.map(s => {
            const inh = runMonteCarlo(s, controlObjectives, controls, 5000, true);
            const res = runMonteCarlo(s, controlObjectives, controls, 5000, false);
            return [
                s.name, s.category||'', s.status||'',
                ((s.freqLow||0)*100).toFixed(1), ((s.freqML||0)*100).toFixed(1), ((s.freqHigh||0)*100).toFixed(1),
                (res.freqReduction*100).toFixed(1), (res.impactReduction*100).toFixed(1),
                inh.percentiles[50].toFixed(0), inh.percentiles[90].toFixed(0), inh.percentiles[99].toFixed(0),
                res.percentiles[50].toFixed(0), res.percentiles[90].toFixed(0), res.percentiles[99].toFixed(0),
            ];
        });
        this._downloadCSV('scenario_summary.csv', [header, ...rows]);
    }

    exportControlsCSV() {
        const header = ['Name','Status','Design%','Scope%','Operating%','Effectiveness%','Owner','Control Objectives'];
        const rows = this.data.controls.map(c => {
            const eff = (c.design||0)/100 * (c.scope||0)/100 * (c.operating||0)/100;
            const coNames = (c.linkedCOs||[]).map(id => this._getCO(id)?.name||'').filter(Boolean).join('; ');
            return [c.name, c.status||'', c.design||0, c.scope||0, c.operating||0, (eff*100).toFixed(1), c.owner||'', coNames];
        });
        this._downloadCSV('controls.csv', [header, ...rows]);
    }

    exportPortfolioJSON() {
        const json = JSON.stringify(this.data, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `cyber_risk_portfolio_${new Date().toISOString().slice(0,10)}.json`;
        a.click();
    }

    _downloadCSV(filename, rows) {
        const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g,'""')}"`).join(',')).join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        a.click();
    }

    // ── Settings ─────────────────────────────────────────────
    renderSettings() {
        const s = this.data.settings;
        document.getElementById('settingsContent').innerHTML = `
        <div class="section-header"><div><h2>Settings</h2></div></div>
        <div class="settings-section">
            <h3>Organization</h3>
            <div class="form-row-2">
                <div class="form-group">
                    <label>Organization Name</label>
                    <input type="text" id="settOrgName" class="form-input" value="${esc(s.orgName||'')}">
                </div>
                <div class="form-group">
                    <label>Currency</label>
                    <select id="settCurrency" class="form-input">
                        ${['USD','EUR','GBP','CAD','AUD'].map(c=>`<option value="${c}" ${s.currency===c?'selected':''}>${c}</option>`).join('')}
                    </select>
                </div>
            </div>
            <div class="form-group">
                <label>Simulation Iterations</label>
                <select id="settIterations" class="form-input">
                    ${[1000,5000,10000,50000].map(n=>`<option value="${n}" ${(s.simIterations||10000)==n?'selected':''}>${n.toLocaleString()}</option>`).join('')}
                </select>
                <div class="form-hint">Higher iterations give more accurate results but are slower.</div>
            </div>
            <button class="btn-primary" onclick="crq.saveSettings()">Save Settings</button>
        </div>
        <div class="settings-section">
            <h3>Sample Data</h3>
            <p style="font-size:0.875rem;color:var(--text-secondary);margin-bottom:12px">Load a pre-built dataset with 5 risk events, 6 control objectives, and 9 controls to explore the app.</p>
            <button class="btn-secondary" onclick="crq.loadSampleData()" style="border-color:var(--warning);color:var(--warning)">⚠ Load Sample Data (replaces all current data)</button>
        </div>

        <div class="settings-section">
            <h3>Database Setup</h3>
            <p style="font-size:0.875rem;color:var(--text-secondary);margin-bottom:12px">Run the following SQL in your Supabase SQL editor to create the required table:</p>
            <pre style="background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-md);padding:16px;font-size:0.8rem;overflow-x:auto;white-space:pre-wrap">CREATE TABLE IF NOT EXISTS cyber_risk_data (
  id          uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id     uuid REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL UNIQUE,
  data        jsonb NOT NULL DEFAULT '{}',
  updated_at  timestamptz DEFAULT now()
);
ALTER TABLE cyber_risk_data ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users manage own data" ON cyber_risk_data
  FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);</pre>
        </div>`;
    }

    loadSampleData() {
        if (!confirm('This will replace all current data with sample data. Continue?')) return;

        const co1 = 'co-email-sec',    co2 = 'co-iam',       co3 = 'co-edr',
              co4 = 'co-dlp',          co5 = 'co-backup',     co6 = 'co-vulnmgmt';

        const c1  = 'ctrl-mfa',        c2  = 'ctrl-email-gw', c3  = 'ctrl-sat',
              c4  = 'ctrl-edr',        c5  = 'ctrl-pam',      c6  = 'ctrl-backup',
              c7  = 'ctrl-dlp',        c8  = 'ctrl-patch',    c9  = 'ctrl-netseg';

        const s1  = 'sc-ransomware',   s2  = 'sc-databreach', s3  = 'sc-bec',
              s4  = 'sc-supplychain',  s5  = 'sc-insider';

        const now = new Date().toISOString();

        this.data.scenarios = [
            {
                id: s1, name: 'Ransomware / Extortion Attack',
                description: 'Threat actor gains access via phishing or exposed RDP, deploys ransomware across the environment, and demands payment. Includes double-extortion (data exfil before encryption).',
                category: 'Ransomware / Extortion', status: 'Active',
                freqLow: 0.05, freqML: 0.15, freqHigh: 0.30,
                impact_response:    { low: 200000,  ml: 750000,   high: 2000000  },
                impact_regulatory:  { low: 0,       ml: 100000,   high: 500000   },
                impact_legal:       { low: 50000,   ml: 200000,   high: 1000000  },
                impact_lostNewBiz:  { low: 100000,  ml: 500000,   high: 2000000  },
                impact_lostExistBiz:{ low: 200000,  ml: 1000000,  high: 5000000  },
                linkedCOs: [co1, co2, co3, co5],
                mitreTechniques: ['T1566', 'T1566.001', 'T1566.002', 'T1078', 'T1486', 'T1490', 'T1489', 'T1562', 'T1562.001'],
                createdAt: now, updatedAt: now,
            },
            {
                id: s2, name: 'Data Breach / Exfiltration',
                description: 'Attacker exfiltrates sensitive customer or employee PII/PHI. Includes notification costs, regulatory fines, and reputational damage from public disclosure.',
                category: 'Data Breach / Exfiltration', status: 'Active',
                freqLow: 0.08, freqML: 0.18, freqHigh: 0.35,
                impact_response:    { low: 150000,  ml: 500000,   high: 1500000  },
                impact_regulatory:  { low: 500000,  ml: 2000000,  high: 8000000  },
                impact_legal:       { low: 200000,  ml: 1000000,  high: 5000000  },
                impact_lostNewBiz:  { low: 500000,  ml: 2000000,  high: 8000000  },
                impact_lostExistBiz:{ low: 1000000, ml: 3000000,  high: 10000000 },
                linkedCOs: [co1, co2, co3, co4, co6],
                mitreTechniques: ['T1566', 'T1078', 'T1078.002', 'T1003', 'T1003.001', 'T1041', 'T1567', 'T1560'],
                createdAt: now, updatedAt: now,
            },
            {
                id: s3, name: 'Business Email Compromise (BEC)',
                description: 'Attacker compromises or impersonates executive email to redirect wire transfers or manipulate financial processes. High frequency, variable financial impact.',
                category: 'Business Email Compromise', status: 'Active',
                freqLow: 0.15, freqML: 0.30, freqHigh: 0.55,
                impact_response:    { low: 25000,   ml: 100000,   high: 300000   },
                impact_regulatory:  { low: 0,       ml: 0,        high: 100000   },
                impact_legal:       { low: 50000,   ml: 200000,   high: 1000000  },
                impact_lostNewBiz:  { low: 0,       ml: 100000,   high: 500000   },
                impact_lostExistBiz:{ low: 50000,   ml: 500000,   high: 3000000  },
                linkedCOs: [co1, co2],
                mitreTechniques: ['T1566', 'T1566.002', 'T1078', 'T1534', 'T1586'],
                createdAt: now, updatedAt: now,
            },
            {
                id: s4, name: 'Third-Party / Supply Chain Compromise',
                description: 'A trusted vendor or software supplier is compromised, providing attackers with privileged access to our environment. Difficult to detect due to legitimate credentials.',
                category: 'Third-Party / Supply Chain', status: 'Active',
                freqLow: 0.03, freqML: 0.08, freqHigh: 0.18,
                impact_response:    { low: 300000,  ml: 1000000,  high: 3000000  },
                impact_regulatory:  { low: 100000,  ml: 500000,   high: 2000000  },
                impact_legal:       { low: 100000,  ml: 500000,   high: 3000000  },
                impact_lostNewBiz:  { low: 200000,  ml: 1000000,  high: 5000000  },
                impact_lostExistBiz:{ low: 500000,  ml: 2000000,  high: 8000000  },
                linkedCOs: [co2, co3, co6],
                mitreTechniques: ['T1195', 'T1195.001', 'T1195.002', 'T1078', 'T1078.004', 'T1505'],
                createdAt: now, updatedAt: now,
            },
            {
                id: s5, name: 'Malicious Insider / Data Theft',
                description: 'A current or former employee intentionally exfiltrates sensitive data for financial gain, competitive advantage, or sabotage. Often bypasses perimeter controls.',
                category: 'Insider Threat', status: 'Active',
                freqLow: 0.04, freqML: 0.10, freqHigh: 0.20,
                impact_response:    { low: 100000,  ml: 300000,   high: 800000   },
                impact_regulatory:  { low: 200000,  ml: 800000,   high: 3000000  },
                impact_legal:       { low: 200000,  ml: 1000000,  high: 4000000  },
                impact_lostNewBiz:  { low: 100000,  ml: 500000,   high: 2000000  },
                impact_lostExistBiz:{ low: 200000,  ml: 1000000,  high: 4000000  },
                linkedCOs: [co2, co4, co3],
                mitreTechniques: ['T1078', 'T1078.003', 'T1213', 'T1048', 'T1048.003', 'T1560'],
                createdAt: now, updatedAt: now,
            },
        ];

        this.data.controlObjectives = [
            {
                id: co1, name: 'Email Security & Anti-Phishing',
                description: 'Prevent malicious emails from reaching users and reduce the likelihood users act on social engineering attempts.',
                maxFreqReduction: 30, maxImpactReduction: 15,
                mitreMitigations: ['M1049', 'M1021', 'M1017'],
                createdAt: now, updatedAt: now,
            },
            {
                id: co2, name: 'Identity & Access Management',
                description: 'Ensure only authorized users can access systems and data, using strong authentication and least-privilege principles.',
                maxFreqReduction: 25, maxImpactReduction: 25,
                mitreMitigations: ['M1032', 'M1026', 'M1027', 'M1018'],
                createdAt: now, updatedAt: now,
            },
            {
                id: co3, name: 'Endpoint Detection & Response',
                description: 'Detect and contain malicious activity on endpoints before attackers can achieve their objectives.',
                maxFreqReduction: 20, maxImpactReduction: 35,
                mitreMitigations: ['M1049', 'M1038', 'M1050'],
                createdAt: now, updatedAt: now,
            },
            {
                id: co4, name: 'Data Loss Prevention',
                description: 'Detect and block unauthorized exfiltration of sensitive data across all channels.',
                maxFreqReduction: 8, maxImpactReduction: 30,
                mitreMitigations: ['M1057', 'M1037'],
                createdAt: now, updatedAt: now,
            },
            {
                id: co5, name: 'Backup & Recovery Capability',
                description: 'Ensure critical data and systems can be restored rapidly to minimize business impact from a destructive attack.',
                maxFreqReduction: 0, maxImpactReduction: 45,
                mitreMitigations: ['M1053'],
                createdAt: now, updatedAt: now,
            },
            {
                id: co6, name: 'Vulnerability Management',
                description: 'Identify and remediate exploitable vulnerabilities before attackers can leverage them for initial access or lateral movement.',
                maxFreqReduction: 22, maxImpactReduction: 15,
                mitreMitigations: ['M1016', 'M1050', 'M1048'],
                createdAt: now, updatedAt: now,
            },
        ];

        this.data.controls = [
            {
                id: c1, name: 'Multi-Factor Authentication (MFA)',
                description: 'Phishing-resistant MFA enforced for all remote access, cloud services, and privileged accounts via hardware tokens and authenticator apps.',
                status: 'Active', owner: 'Identity Team',
                design: 90, scope: 82, operating: 78,
                linkedCOs: [co2],
                mitreTechniques: ['T1078', 'T1078.002', 'T1078.004', 'T1110', 'T1110.003', 'T1110.004', 'T1558'],
                reviewDate: '2025-06-01', createdAt: now, updatedAt: now,
            },
            {
                id: c2, name: 'Email Gateway / Anti-Phishing Filter',
                description: 'Cloud email security platform with sandboxing, link rewriting, impersonation protection, and DMARC enforcement.',
                status: 'Active', owner: 'Security Operations',
                design: 80, scope: 100, operating: 85,
                linkedCOs: [co1],
                mitreTechniques: ['T1566', 'T1566.001', 'T1566.002', 'T1566.003'],
                reviewDate: '2025-04-01', createdAt: now, updatedAt: now,
            },
            {
                id: c3, name: 'Security Awareness Training',
                description: 'Quarterly phishing simulations and annual security training for all employees. Metrics tracked by department.',
                status: 'Active', owner: 'HR / Security',
                design: 65, scope: 98, operating: 72,
                linkedCOs: [co1],
                mitreTechniques: ['T1566', 'T1566.001', 'T1566.002', 'T1566.004', 'T1204'],
                reviewDate: '2025-09-01', createdAt: now, updatedAt: now,
            },
            {
                id: c4, name: 'Endpoint Detection & Response (EDR)',
                description: 'Enterprise EDR deployed across all managed endpoints with 24/7 SOC monitoring and automated containment playbooks.',
                status: 'Active', owner: 'Security Operations',
                design: 88, scope: 87, operating: 80,
                linkedCOs: [co3],
                mitreTechniques: ['T1486', 'T1490', 'T1489', 'T1562', 'T1562.001', 'T1059', 'T1059.001', 'T1055'],
                reviewDate: '2025-07-01', createdAt: now, updatedAt: now,
            },
            {
                id: c5, name: 'Privileged Access Management (PAM)',
                description: 'PAM solution managing all privileged credentials with session recording, just-in-time access, and regular certification.',
                status: 'Active', owner: 'Identity Team',
                design: 85, scope: 70, operating: 68,
                linkedCOs: [co2],
                mitreTechniques: ['T1078', 'T1078.002', 'T1003', 'T1003.001', 'T1550'],
                reviewDate: '2025-08-01', createdAt: now, updatedAt: now,
            },
            {
                id: c6, name: 'Backup & Immutable Recovery',
                description: 'Daily encrypted backups to air-gapped immutable storage. Recovery tested quarterly with < 4hr RTO for critical systems.',
                status: 'Active', owner: 'Infrastructure',
                design: 92, scope: 80, operating: 76,
                linkedCOs: [co5],
                mitreTechniques: ['T1486', 'T1490', 'T1485'],
                reviewDate: '2025-05-01', createdAt: now, updatedAt: now,
            },
            {
                id: c7, name: 'Data Loss Prevention (DLP)',
                description: 'DLP policies enforced on email, cloud storage, and endpoints. Sensitive data classification applied to PII, PCI, and IP.',
                status: 'Under Review', owner: 'Data Governance',
                design: 72, scope: 75, operating: 60,
                linkedCOs: [co4],
                mitreTechniques: ['T1048', 'T1048.001', 'T1048.003', 'T1041', 'T1567'],
                reviewDate: '2025-03-01', createdAt: now, updatedAt: now,
            },
            {
                id: c8, name: 'Vulnerability Scanning & Patch Management',
                description: 'Weekly authenticated vulnerability scans with risk-based patching SLAs: Critical 7 days, High 30 days, Medium 90 days.',
                status: 'Active', owner: 'IT Operations',
                design: 78, scope: 88, operating: 72,
                linkedCOs: [co6],
                mitreTechniques: ['T1190', 'T1068', 'T1595', 'T1595.002'],
                reviewDate: '2025-06-01', createdAt: now, updatedAt: now,
            },
            {
                id: c9, name: 'Network Segmentation & Zero Trust',
                description: 'Micro-segmentation applied to critical systems. ZTNA deployed for remote access replacing legacy VPN.',
                status: 'Draft', owner: 'Network Engineering',
                design: 80, scope: 55, operating: 70,
                linkedCOs: [co3, co4],
                mitreTechniques: ['T1021', 'T1021.001', 'T1021.002', 'T1570', 'T1090'],
                reviewDate: '2025-12-01', createdAt: now, updatedAt: now,
            },
        ];

        this.data.settings = {
            orgName: 'Acme Corporation',
            currency: 'USD',
            simIterations: 10000,
        };

        this._simCache = {};
        this.saveData().then(() => {
            document.getElementById('orgNameDisplay').textContent = 'Acme Corporation';
            this.showView('dashboard');
            alert('Sample data loaded — 5 risk events, 6 control objectives, 9 controls.');
        });
    }

    saveSettings() {
        this.data.settings = {
            orgName: document.getElementById('settOrgName').value.trim(),
            currency: document.getElementById('settCurrency').value,
            simIterations: parseInt(document.getElementById('settIterations').value),
        };
        document.getElementById('orgNameDisplay').textContent = this.data.settings.orgName;
        this.saveData().then(() => {
            const btn = document.querySelector('#settingsContent .btn-primary');
            if (btn) { btn.textContent = 'Saved ✓'; setTimeout(() => btn.textContent = 'Save Settings', 2000); }
        });
    }

    // ── Full Screen Form ──────────────────────────────────────
    openFullScreenForm(type, item) {
        this._formType = type;
        this._formItem = item || null;
        const isEdit = !!item;
        const titles = { scenarios: 'Risk Event', controlObjectives: 'Control Objective', controls: 'Control' };
        document.getElementById('fullScreenFormTitle').textContent = (isEdit ? 'Edit ' : 'New ') + (titles[type] || type);
        document.getElementById('fullScreenFormFields').innerHTML = this._buildFormFields(type, item);
        document.getElementById('fullScreenForm').classList.add('open');
        window.scrollTo(0, 0);
    }

    _buildFormFields(type, item) {
        const v = item || {};
        if (type === 'scenarios') return this._scenarioFormFields(v);
        if (type === 'controlObjectives') return this._coFormFields(v);
        if (type === 'controls') return this._controlFormFields(v);
        return '';
    }

    _scenarioFormFields(v) {
        const statusOpts = ['Active','Draft','Under Review','Archived'].map(s => `<option value="${s}" ${v.status===s?'selected':''}>${s}</option>`).join('');
        const catOpts = RISK_CATEGORIES.map(c => `<option value="${c}" ${v.category===c?'selected':''}>${c}</option>`).join('');

        const impactSection = IMPACT_CATS.map(cat => {
            const imp = v['impact_' + cat.id] || {};
            return `<div class="form-section-title">${cat.label}</div>
            <div class="form-row" style="margin-bottom:4px">
                <div class="form-group">
                    <label>Low ($)</label>
                    <input type="number" id="imp_${cat.id}_low" class="form-input" value="${imp.low||''}" placeholder="0" min="0">
                </div>
                <div class="form-group">
                    <label>Most Likely ($)</label>
                    <input type="number" id="imp_${cat.id}_ml" class="form-input" value="${imp.ml||''}" placeholder="0" min="0">
                </div>
                <div class="form-group">
                    <label>High ($)</label>
                    <input type="number" id="imp_${cat.id}_high" class="form-input" value="${imp.high||''}" placeholder="0" min="0">
                </div>
            </div>`;
        }).join('');

        const mitreSection = this._mitreCheckboxes('mitreTechniques_', v.mitreTechniques || []);

        return `
        <div class="form-row-2">
            <div class="form-group">
                <label>Risk Event Name *</label>
                <input type="text" id="f_name" class="form-input" value="${esc(v.name||'')}" required>
            </div>
            <div class="form-group">
                <label>Category</label>
                <select id="f_category" class="form-input"><option value="">— Select —</option>${catOpts}</select>
            </div>
        </div>
        <div class="form-group">
            <label>Description</label>
            <textarea id="f_description" class="form-input">${esc(v.description||'')}</textarea>
        </div>
        <div class="form-group">
            <label>Status</label>
            <select id="f_status" class="form-input">${statusOpts}</select>
        </div>

        <div class="form-section-title">Frequency — Annual Probability of Loss (0–1)</div>
        <div class="form-row">
            <div class="form-group">
                <label>Low</label>
                <input type="number" id="f_freqLow" class="form-input" value="${v.freqLow??''}" step="0.001" min="0" max="1" placeholder="0.01">
                <div class="form-hint">e.g. 0.05 = 5% chance per year</div>
            </div>
            <div class="form-group">
                <label>Most Likely</label>
                <input type="number" id="f_freqML" class="form-input" value="${v.freqML??''}" step="0.001" min="0" max="1" placeholder="0.10">
            </div>
            <div class="form-group">
                <label>High</label>
                <input type="number" id="f_freqHigh" class="form-input" value="${v.freqHigh??''}" step="0.001" min="0" max="1" placeholder="0.30">
            </div>
        </div>

        <div class="form-section-title">Impact Categories (Dollar Estimates)</div>
        ${impactSection}

        <div class="form-section-title">MITRE ATT&amp;CK Techniques (Associated with this Risk Event)</div>
        ${mitreSection}`;
    }

    _coFormFields(v) {
        return `
        <div class="form-group">
            <label>Control Objective Name *</label>
            <input type="text" id="f_name" class="form-input" value="${esc(v.name||'')}" required>
        </div>
        <div class="form-group">
            <label>Description</label>
            <textarea id="f_description" class="form-input">${esc(v.description||'')}</textarea>
        </div>
        <div class="form-row-2">
            <div class="form-group">
                <label>Max Frequency Reduction (%)</label>
                <input type="number" id="f_maxFreqReduction" class="form-input" value="${v.maxFreqReduction??''}" min="0" max="100" placeholder="20">
                <div class="form-hint">Max % reduction in annual probability if this CO is fully achieved</div>
            </div>
            <div class="form-group">
                <label>Max Impact Reduction (%)</label>
                <input type="number" id="f_maxImpactReduction" class="form-input" value="${v.maxImpactReduction??''}" min="0" max="100" placeholder="30">
                <div class="form-hint">Max % reduction in loss severity if this CO is fully achieved</div>
            </div>
        </div>
        <div class="form-section-title">MITRE ATT&amp;CK Mitigations</div>
        <div style="display:flex;flex-wrap:wrap;gap:8px;">
            ${MITRE_MITIGATIONS.map(m => `
            <label style="display:flex;align-items:center;gap:5px;font-size:0.82rem;cursor:pointer">
                <input type="checkbox" name="mitreMitigations_" value="${m.id}" ${(v.mitreMitigations||[]).includes(m.id)?'checked':''}>
                ${esc(m.name)}
            </label>`).join('')}
        </div>`;
    }

    _controlFormFields(v) {
        const statusOpts = ['Active','Draft','Under Review','Inactive'].map(s => `<option value="${s}" ${v.status===s?'selected':''}>${s}</option>`).join('');
        const mitreSection = this._mitreCheckboxes('mitreTechniques_', v.mitreTechniques || []);

        return `
        <div class="form-group">
            <label>Control Name *</label>
            <input type="text" id="f_name" class="form-input" value="${esc(v.name||'')}" required>
        </div>
        <div class="form-group">
            <label>Description</label>
            <textarea id="f_description" class="form-input">${esc(v.description||'')}</textarea>
        </div>
        <div class="form-row-2">
            <div class="form-group">
                <label>Owner</label>
                <input type="text" id="f_owner" class="form-input" value="${esc(v.owner||'')}">
            </div>
            <div class="form-group">
                <label>Status</label>
                <select id="f_status" class="form-input">${statusOpts}</select>
            </div>
        </div>
        <div class="form-group">
            <label>Review Date</label>
            <input type="date" id="f_reviewDate" class="form-input" value="${v.reviewDate||''}">
        </div>

        <div class="form-section-title">Effectiveness Ratings</div>
        <div class="form-row">
            <div class="form-group">
                <label>Design (%)</label>
                <input type="number" id="f_design" class="form-input" value="${v.design??''}" min="0" max="100" placeholder="80">
                <div class="form-hint">% of objective achieved if fully effective</div>
            </div>
            <div class="form-group">
                <label>Scope (%)</label>
                <input type="number" id="f_scope" class="form-input" value="${v.scope??''}" min="0" max="100" placeholder="100">
                <div class="form-hint">% of environment / assets covered</div>
            </div>
            <div class="form-group">
                <label>Operating Effectiveness (%)</label>
                <input type="number" id="f_operating" class="form-input" value="${v.operating??''}" min="0" max="100" placeholder="90">
                <div class="form-hint">How consistently it operates within its scope</div>
            </div>
        </div>

        <div class="form-section-title">MITRE ATT&amp;CK Techniques Addressed</div>
        ${mitreSection}`;
    }

    _mitreCheckboxes(namePrefix, selected) {
        return `<div style="max-height:320px;overflow-y:auto;border:1px solid var(--border);border-radius:var(--radius-md);padding:10px">
            ${MITRE_TACTICS.map(tactic => {
                const techs = MITRE_TECHNIQUES.filter(t => t.tactic === tactic.id);
                return `<div style="margin-bottom:14px">
                    <div style="font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-secondary);margin-bottom:6px">${tactic.name}</div>
                    ${techs.map(t => {
                        const subs = MITRE_SUBTECHNIQUES.filter(s => s.parentId === t.id);
                        const techChecked = selected.includes(t.id);
                        const techLabel = `<label class="mitre-cb-row" style="background:${techChecked?'var(--primary-light)':'var(--bg)'}">
                            <input type="checkbox" name="${namePrefix}" value="${t.id}" ${techChecked?'checked':''}
                                onchange="this.closest('.mitre-cb-row').style.background=this.checked?'var(--primary-light)':'var(--bg)'">
                            <span style="font-size:0.8rem;font-weight:500">${esc(t.name)}</span>
                            <span style="font-size:0.7rem;color:var(--text-tertiary);margin-left:4px">${t.id}</span>
                        </label>`;
                        const subsHtml = subs.length > 0 ? `<div style="padding-left:18px;display:flex;flex-direction:column;gap:2px;margin-bottom:4px">
                            ${subs.map(s => {
                                const subChecked = selected.includes(s.id);
                                return `<label class="mitre-cb-row mitre-cb-sub" style="background:${subChecked?'var(--primary-light)':'transparent'}">
                                    <input type="checkbox" name="${namePrefix}" value="${s.id}" ${subChecked?'checked':''}
                                        onchange="this.closest('.mitre-cb-row').style.background=this.checked?'var(--primary-light)':'transparent'">
                                    <span style="font-size:0.75rem">${esc(s.name)}</span>
                                    <span style="font-size:0.68rem;color:var(--text-tertiary);margin-left:4px">${s.id}</span>
                                </label>`;
                            }).join('')}
                        </div>` : '';
                        return techLabel + subsHtml;
                    }).join('')}
                </div>`;
            }).join('')}
        </div>`;
    }

    closeFullScreenForm() {
        document.getElementById('fullScreenForm').classList.remove('open');
        this._formType = null;
        this._formItem = null;
    }

    handleSubmit(event) {
        event.preventDefault();
        const type = this._formType;
        const existing = this._formItem;
        const now = new Date().toISOString();
        const g = id => (document.getElementById(id)?.value || '').trim();
        const gn = id => { const v = parseFloat(document.getElementById(id)?.value); return isNaN(v) ? null : v; };
        const gcb = name => Array.from(document.querySelectorAll(`input[name="${name}"]:checked`)).map(cb => cb.value);

        let item;

        if (type === 'scenarios') {
            item = {
                id: existing?.id || uuid(),
                name: g('f_name'),
                description: g('f_description'),
                category: g('f_category'),
                status: g('f_status') || 'Draft',
                freqLow:  gn('f_freqLow'),
                freqML:   gn('f_freqML'),
                freqHigh: gn('f_freqHigh'),
                linkedCOs: existing?.linkedCOs || [],
                mitreTechniques: gcb('mitreTechniques_'),
                createdAt: existing?.createdAt || now,
                updatedAt: now,
            };
            IMPACT_CATS.forEach(cat => {
                item['impact_' + cat.id] = {
                    low:  parseFloat(document.getElementById(`imp_${cat.id}_low`)?.value)  || 0,
                    ml:   parseFloat(document.getElementById(`imp_${cat.id}_ml`)?.value)   || 0,
                    high: parseFloat(document.getElementById(`imp_${cat.id}_high`)?.value) || 0,
                };
            });
        } else if (type === 'controlObjectives') {
            item = {
                id: existing?.id || uuid(),
                name: g('f_name'),
                description: g('f_description'),
                maxFreqReduction:   parseFloat(g('f_maxFreqReduction'))   || 0,
                maxImpactReduction: parseFloat(g('f_maxImpactReduction')) || 0,
                mitreMitigations: gcb('mitreMitigations_'),
                createdAt: existing?.createdAt || now,
                updatedAt: now,
            };
        } else if (type === 'controls') {
            item = {
                id: existing?.id || uuid(),
                name: g('f_name'),
                description: g('f_description'),
                owner: g('f_owner'),
                status: g('f_status') || 'Draft',
                design:    parseFloat(g('f_design'))    || 0,
                scope:     parseFloat(g('f_scope'))     || 0,
                operating: parseFloat(g('f_operating')) || 0,
                reviewDate: g('f_reviewDate'),
                linkedCOs: existing?.linkedCOs || [],
                mitreTechniques: gcb('mitreTechniques_'),
                createdAt: existing?.createdAt || now,
                updatedAt: now,
            };
        }

        if (!item || !item.name) return;

        const arr = this.data[type];
        const idx = arr.findIndex(x => x.id === item.id);
        if (idx >= 0) arr[idx] = item;
        else arr.push(item);

        delete this._simCache[item.id];
        this.closeFullScreenForm();
        this.saveData().then(() => {
            if (type === 'scenarios')        { this.renderScenarios(); this.showView('scenarios'); }
            if (type === 'controlObjectives') { this.renderControlObjectives(); this.showView('controlObjectives'); }
            if (type === 'controls')         { this.renderControls(); this.showView('controls'); }
        });
    }

    // ── Delete Modal ─────────────────────────────────────────
    openDeleteModal(type, id) {
        this._deleteTarget = { type, id };
        const item = this.data[type]?.find(x => x.id === id);
        document.getElementById('deleteModal').className = 'modal-overlay open';
        document.getElementById('deleteModalMessage').textContent = `Are you sure you want to delete "${item?.name || 'this item'}"? This cannot be undone.`;
    }

    closeDeleteModal() {
        document.getElementById('deleteModal').className = 'modal-overlay';
        document.getElementById('deleteModal').innerHTML = `
        <div class="modal-card">
            <h3>Confirm Delete</h3>
            <p id="deleteModalMessage">Are you sure?</p>
            <div class="modal-actions">
                <button class="btn-secondary" onclick="crq.closeDeleteModal()">Cancel</button>
                <button class="btn-delete" onclick="crq.confirmDelete()">Delete</button>
            </div>
        </div>`;
        this._deleteTarget = null;
        this._pendingLinkConfirm = null;
    }

    confirmDelete() {
        if (!this._deleteTarget) return;
        const { type, id } = this._deleteTarget;
        this.data[type] = this.data[type].filter(x => x.id !== id);

        // Clean up references
        if (type === 'controlObjectives') {
            this.data.scenarios.forEach(s => s.linkedCOs = (s.linkedCOs||[]).filter(cid => cid !== id));
            this.data.controls.forEach(c => c.linkedCOs = (c.linkedCOs||[]).filter(cid => cid !== id));
        }
        if (type === 'controls') {
            // Just remove — COs recalculate dynamically
        }

        delete this._simCache[id];
        this.closeDeleteModal();
        this.saveData().then(() => {
            if (type === 'scenarios')        this.showView('scenarios');
            if (type === 'controlObjectives') this.showView('controlObjectives');
            if (type === 'controls')         this.showView('controls');
        });
    }
}

// ── Boot ────────────────────────────────────────────────────
window.crq = new CRQApp();
document.addEventListener('DOMContentLoaded', () => crq.init());
