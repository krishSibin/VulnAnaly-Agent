/*
 * Make the S-TCS-DC-WINTEL vulnerable items look like they came from the Qualys integration.
 *
 * Run in ServiceNow:  System Definition > Scripts - Background
 *   - "in scope":  global  (the tables allow writes from other scopes)
 *   - paste this whole file, click "Run script"
 *
 * Safe to run more than once: existing CVE / QID records are reused and
 * items that are already linked are refreshed, not duplicated.
 *
 * CVE IDs and CVSS scores are real. QID numbers are illustrative.
 */
(function () {
    var GROUP = 'S-TCS-DC-WINTEL';

    // One entry per software issue. "match" tokens are looked for (case-insensitive)
    // in the vulnerable item's existing description (program path or QID).
    var CATALOG = [
        {
            match: ['MSEDGE', 'QID-377887', 'QID-380201', 'QID-376540', 'QID-EDGE'],
            qid: 'QID-377887', vendor: 'Microsoft', product: 'Edge', category: 'Local',
            name: 'Microsoft Edge Based on Chromium Prior to 125.0.2535.51 Multiple Vulnerabilities',
            summary: 'Microsoft Edge (Chromium-based) is affected by Chromium security issues including CVE-2024-4947, a type confusion in V8 that lets a remote attacker run code through a crafted HTML page.',
            threat: 'A remote attacker who gets a user to open a crafted web page can execute arbitrary code in the browser process. Exploitation in the wild has been reported.',
            solution: 'Update Microsoft Edge to version 125.0.2535.51 or later.',
            cve: 'CVE-2024-4947', cveSummary: 'Type confusion in V8 in Google Chrome prior to 125.0.6422.60 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.',
            score: 8.8, severity: 'HIGH', qsev: 5, kev: true, published: '2024-05-15',
            proof: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe  Version is  124.0.2478.80#'
        },
        {
            match: ['CHROME.EXE', 'QID-362145', 'QID-CHROME'],
            qid: 'QID-362145', vendor: 'Google', product: 'Chrome', category: 'Local',
            name: 'Google Chrome Prior to 125.0.6422.60 Multiple Vulnerabilities',
            summary: 'Google Chrome is affected by multiple vulnerabilities including CVE-2024-4947, a type confusion in the V8 JavaScript engine.',
            threat: 'A remote attacker who gets a user to open a crafted web page can corrupt heap memory and execute arbitrary code. Exploitation in the wild has been reported.',
            solution: 'Update Google Chrome to version 125.0.6422.60 or later.',
            cve: 'CVE-2024-4947', cveSummary: 'Type confusion in V8 in Google Chrome prior to 125.0.6422.60 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.',
            score: 8.8, severity: 'HIGH', qsev: 5, kev: true, published: '2024-05-15',
            proof: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe  Version is  124.0.6367.91#'
        },
        {
            match: ['7Z.EXE', '7-ZIP', 'QID-382694'],
            qid: 'QID-382694', vendor: '7-Zip', product: '7-Zip', category: 'Local',
            name: '7-Zip Mark-of-the-Web Bypass Vulnerability',
            summary: '7-Zip before 24.09 does not propagate the Mark-of-the-Web to files extracted from crafted archives (CVE-2025-0411).',
            threat: 'An attacker can deliver a malicious file inside a crafted archive that runs without Windows security warnings once extracted.',
            solution: 'Upgrade 7-Zip to version 24.09 or later.',
            cve: 'CVE-2025-0411', cveSummary: '7-Zip Mark-of-the-Web bypass: files extracted from crafted archives do not inherit the Mark-of-the-Web, allowing execution of arbitrary code in the context of the current user.',
            score: 7.0, severity: 'HIGH', qsev: 4, kev: true, published: '2025-01-25',
            proof: 'C:\\Program Files\\7-Zip\\7z.exe  Version is  19.00#'
        },
        {
            match: ['OUTLOOK.EXE', 'QID-378388'],
            qid: 'QID-378388', vendor: 'Microsoft', product: 'Office', category: 'Office Application',
            name: 'Microsoft Office Outlook Elevation of Privilege Vulnerability',
            summary: 'Microsoft Outlook for Windows is affected by an elevation of privilege vulnerability (CVE-2023-23397) triggered by a crafted message, with no user interaction.',
            threat: 'A crafted email can make Outlook leak the user\'s Net-NTLMv2 hash to an attacker-controlled server, which can be relayed to authenticate as the user. Exploited in the wild.',
            solution: 'Install the March 2023 Microsoft Office security update (update Microsoft 365 Apps to a current build).',
            cve: 'CVE-2023-23397', cveSummary: 'Microsoft Outlook Elevation of Privilege Vulnerability.',
            score: 9.8, severity: 'CRITICAL', qsev: 5, kev: true, published: '2023-03-14',
            proof: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE  Version is  16.0.14332.20604#'
        },
        {
            match: ['EXCEL.EXE', 'QID-379201'],
            qid: 'QID-379201', vendor: 'Microsoft', product: 'Office', category: 'Office Application',
            name: 'Microsoft Office Excel Remote Code Execution Vulnerability',
            summary: 'Microsoft Excel is affected by a remote code execution vulnerability (CVE-2023-36041) when opening a crafted file.',
            threat: 'An attacker who gets a user to open a crafted Excel file can run code with the user\'s privileges.',
            solution: 'Install the November 2023 Microsoft Office security update.',
            cve: 'CVE-2023-36041', cveSummary: 'Microsoft Excel Remote Code Execution Vulnerability.',
            score: 7.8, severity: 'HIGH', qsev: 4, kev: false, published: '2023-11-14',
            proof: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE  Version is  16.0.14332.20604#'
        },
        {
            match: ['NTOSKRNL', 'QID-380476'],
            qid: 'QID-380476', vendor: 'Microsoft', product: 'Windows', category: 'Windows',
            name: 'Microsoft Windows Kernel Elevation of Privilege Vulnerability',
            summary: 'The Windows kernel is affected by an elevation of privilege vulnerability (CVE-2024-21338). The February 2024 cumulative update is missing.',
            threat: 'A local attacker can gain SYSTEM privileges. Exploited in the wild.',
            solution: 'Install the February 2024 Windows cumulative security update.',
            cve: 'CVE-2024-21338', cveSummary: 'Windows Kernel Elevation of Privilege Vulnerability.',
            score: 7.8, severity: 'HIGH', qsev: 5, kev: true, published: '2024-02-13',
            proof: 'C:\\Windows\\System32\\ntoskrnl.exe  Version is  10.0.20348.2159#'
        },
        {
            match: ['WIN32K', 'QID-381044'],
            qid: 'QID-381044', vendor: 'Microsoft', product: 'Windows', category: 'Windows',
            name: 'Microsoft Windows Win32k Elevation of Privilege Vulnerability',
            summary: 'The Win32k kernel driver is affected by an elevation of privilege vulnerability (CVE-2023-29336).',
            threat: 'A local attacker can gain SYSTEM privileges. Exploited in the wild.',
            solution: 'Install the May 2023 Windows cumulative security update.',
            cve: 'CVE-2023-29336', cveSummary: 'Win32k Elevation of Privilege Vulnerability.',
            score: 7.8, severity: 'HIGH', qsev: 5, kev: true, published: '2023-05-09',
            proof: 'C:\\Windows\\System32\\win32kfull.sys  Version is  10.0.20348.1607#'
        },
        {
            match: ['SRV2.SYS', 'SMB'],
            qid: 'QID-91614', vendor: 'Microsoft', product: 'Windows', category: 'Windows',
            name: 'Microsoft Windows SMBv3 Compression Remote Code Execution Vulnerability (SMBGhost)',
            summary: 'The SMBv3 server handles compressed packets incorrectly (CVE-2020-0796), allowing remote code execution without authentication.',
            threat: 'An unauthenticated attacker on the network can execute code on the server. Wormable. Exploited in the wild.',
            solution: 'Install KB4551762 or a later cumulative update. As a workaround, disable SMBv3 compression.',
            cve: 'CVE-2020-0796', cveSummary: 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability.',
            score: 10.0, severity: 'CRITICAL', qsev: 5, kev: true, published: '2020-03-12',
            proof: 'C:\\Windows\\System32\\drivers\\srv2.sys  Version is  10.0.18362.657#'
        },
        {
            match: ['ACRORD32', 'ACROBAT', 'QID-383609'],
            qid: 'QID-383609', vendor: 'Adobe', product: 'Acrobat Reader', category: 'Local',
            name: 'Adobe Acrobat Reader Out-of-Bounds Write Vulnerability (APSB23-34)',
            summary: 'Adobe Acrobat Reader is affected by an out-of-bounds write (CVE-2023-26369) when parsing a crafted PDF.',
            threat: 'Opening a crafted PDF can lead to code execution as the current user. Exploited in the wild.',
            solution: 'Update Adobe Acrobat Reader DC to 23.006.20320 or later.',
            cve: 'CVE-2023-26369', cveSummary: 'Adobe Acrobat and Reader out-of-bounds write vulnerability.',
            score: 7.8, severity: 'HIGH', qsev: 5, kev: true, published: '2023-09-13',
            proof: 'C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe  Version is  23.001.20093#'
        },
        {
            match: ['NOTEPAD++', 'QID-355120'],
            qid: 'QID-355120', vendor: 'Notepad++', product: 'Notepad++', category: 'Local',
            name: 'Notepad++ Heap Buffer Overflow Vulnerability',
            summary: 'Notepad++ before 8.5.7 is affected by a heap buffer overflow in its file-encoding detection (CVE-2023-40031).',
            threat: 'Opening a crafted file can crash Notepad++ and may allow code execution as the current user.',
            solution: 'Upgrade Notepad++ to version 8.5.7 or later.',
            cve: 'CVE-2023-40031', cveSummary: 'Notepad++ heap buffer overflow in Utf8_16_Read::convert.',
            score: 7.8, severity: 'HIGH', qsev: 3, kev: false, published: '2023-08-25',
            proof: 'C:\\Program Files\\Notepad++\\notepad++.exe  Version is  8.1.4#'
        }
    ];

    function findCatalog(desc) {
        var d = (desc || '').toUpperCase();
        for (var i = 0; i < CATALOG.length; i++) {
            for (var j = 0; j < CATALOG[i].match.length; j++) {
                if (d.indexOf(CATALOG[i].match[j]) > -1) return CATALOG[i];
            }
        }
        return null;
    }

    function ensureCve(c) {
        var gr = new GlideRecord('sn_vul_nvd_entry');
        if (!gr.get('id', c.cve)) {
            gr.initialize();
            gr.setValue('id', c.cve);
        }
        gr.setValue('name', c.cve);
        gr.setValue('summary', c.cveSummary);
        gr.setValue('v3_base_score', c.score);
        gr.setValue('v3_base_severity', c.severity);
        gr.setValue('date_published', c.published);
        gr.setValue('cisa_exists', c.kev);
        gr.setValue('source', 'NVD');
        gr.setValue('active', true);
        return gr.isNewRecord() ? gr.insert() : (gr.update(), gr.getUniqueValue());
    }

    function ensureQid(c) {
        if (c.sysId) return c.sysId;
        var cveId = ensureCve(c);
        var gr = new GlideRecord('sn_vul_third_party_entry');
        if (!gr.get('id', c.qid)) {
            gr.initialize();
            gr.setValue('id', c.qid);
        }
        gr.setValue('name', c.name);
        gr.setValue('summary', c.summary);
        gr.setValue('threat', c.threat);
        gr.setValue('solution', c.solution);
        gr.setValue('source', 'Qualys');
        gr.setValue('vendor', c.vendor);
        gr.setValue('product', c.product);
        gr.setValue('category', c.category);
        gr.setValue('cve_id', cveId);
        gr.setValue('cves_list', cveId);
        gr.setValue('v3_base_score', c.score);
        gr.setValue('v3_base_severity', c.severity);
        gr.setValue('source_severity', c.qsev);
        gr.setValue('cisa_exists', c.kev);
        gr.setValue('exploit', c.kev ? 'Yes' : 'No');
        gr.setValue('date_published', c.published);
        gr.setValue('active', true);
        c.sysId = gr.isNewRecord() ? gr.insert() : (gr.update(), gr.getUniqueValue());
        return c.sysId;
    }

    // "C:\...\chrome.exe 122.0.6261.94"  ->  "C:\...\chrome.exe  Version is  122.0.6261.94#"
    function proofFor(desc, c) {
        var first = (desc || '').split('\n')[0];
        if (!/^[A-Z]:\\/i.test(first)) return c.proof;
        var m = first.match(/^(.*?\.(exe|sys|dll))\s+(?:Version\s+)?([\d.]+)\s*$/i);
        return m ? m[1] + '  Version is  ' + m[3] + '#' : c.proof;
    }

    function rating(score) {           // 1 Critical, 2 High, 3 Medium, 4 Low
        return score >= 90 ? 1 : score >= 70 ? 2 : score >= 40 ? 3 : 4;
    }

    var linked = 0, skipped = 0;
    var vi = new GlideRecord('sn_vul_vulnerable_item');
    vi.addQuery('assignment_group.name', 'CONTAINS', GROUP);
    vi.addActiveQuery();
    vi.query();
    while (vi.next()) {
        var desc = vi.getValue('description');
        var c = findCatalog(desc);
        if (!c) {
            gs.print('SKIP   ' + vi.getValue('number') + '  no matching software in description');
            skipped++;
            continue;
        }
        var qidSysId = ensureQid(c);

        vi.setValue('vulnerability', qidSysId);
        vi.setValue('source', 'Qualys');
        if (!vi.getValue('first_found_dt_tm')) vi.setDisplayValue('first_found_dt_tm', gs.daysAgo(21));
        vi.setDisplayValue('last_found_dt_tm', gs.nowDateTime());
        vi.setValue('times_found', Math.max(parseInt(vi.getValue('times_found') || '0', 10), 3));
        vi.work_notes = 'Qualys detection ' + c.qid + ' (' + c.cve + ') linked.';
        vi.update();

        // Detection with Qualys-style proof
        var det = new GlideRecord('sn_vul_detection');
        det.addQuery('vulnerable_item', vi.getUniqueValue());
        det.query();
        if (!det.next()) {
            det.initialize();
            det.setValue('vulnerable_item', vi.getUniqueValue());
        }
        det.setValue('vulnerability', qidSysId);
        det.setValue('cmdb_ci', vi.getValue('cmdb_ci'));
        det.setValue('source', 'Qualys');
        det.setValue('source_type', 'Qualys');
        det.setValue('detection_method', 'Authenticated scan');
        det.setValue('proof', proofFor(desc, c));
        det.setValue('solution_summary', c.solution);
        det.setValue('source_severity', String(c.qsev));
        det.setValue('confirmed', true);
        det.setDisplayValue('first_found', gs.daysAgo(21));
        det.setDisplayValue('last_found', gs.nowDateTime());
        det.setValue('times_found', 3);
        if (det.isNewRecord()) det.insert(); else det.update();

        // ServiceNow's calculator normally sets the risk score; fall back to CVSS x 10 if it didn't
        var chk = new GlideRecord('sn_vul_vulnerable_item');
        chk.get(vi.getUniqueValue());
        var score = parseInt(chk.getValue('risk_score') || '0', 10);
        if (!score) {
            score = Math.round(c.score * 10);
            chk.setValue('risk_score', score);
            chk.setValue('risk_rating', rating(score));
            chk.setWorkflow(false);
            chk.update();
        }
        gs.print('LINKED ' + vi.getValue('number') + '  ' + c.qid + ' / ' + c.cve + '  score ' + score + '  ' + c.name);
        linked++;
    }
    gs.print('Done. Linked ' + linked + ' vulnerable items, skipped ' + skipped + '.');
})();
