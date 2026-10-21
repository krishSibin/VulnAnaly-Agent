/*
 * Step 2 after qualys_demo_data.js: give the Qualys vulnerabilities and their
 * vulnerable items proper risk scores.
 *
 * Records created by a script don't go through the integration's calculators, so the
 * vulnerabilities stay at risk 0 / "5 - None" and the items fall back to 10 / "4 - Low".
 * This sets the vulnerability scores from CVSS, then re-saves the items so ServiceNow
 * recalculates; any item still below its vulnerability's score is set to it directly.
 *
 * Run in ServiceNow:  System Definition > Scripts - Background, in scope: global.
 * Safe to run more than once.
 */
(function () {
    var GROUP = 'S-TCS-DC-WINTEL';

    // 1 Critical, 2 High, 3 Medium, 4 Low
    function rating(score) {
        return score >= 90 ? 1 : score >= 70 ? 2 : score >= 40 ? 3 : 4;
    }

    // 1) Vulnerabilities: risk score = CVSS v3 x 10
    var vulScores = {};
    var ent = new GlideRecord('sn_vul_entry');
    ent.addQuery('source', 'IN', 'Qualys,NVD');
    ent.addNotNullQuery('v3_base_score');
    ent.query();
    while (ent.next()) {
        var score = Math.round(parseFloat(ent.getValue('v3_base_score')) * 10);
        if (!score) continue;
        ent.setValue('risk_score', score);
        ent.setValue('risk_rating', rating(score));
        ent.setValue('normalized_severity', rating(score));
        ent.setValue('source_risk_score', score);
        ent.update();
        vulScores[ent.getUniqueValue()] = score;
        gs.print('VULN   ' + ent.getValue('id') + '  CVSS ' + ent.getValue('v3_base_score') + '  ->  risk ' + score);
    }

    // 2) Vulnerable items: recalculate, then make sure they're not below their vulnerability
    var fixed = 0, calculated = 0;
    var vi = new GlideRecord('sn_vul_vulnerable_item');
    vi.addQuery('assignment_group.name', 'CONTAINS', GROUP);
    vi.addActiveQuery();
    vi.addNotNullQuery('vulnerability');
    vi.query();
    while (vi.next()) {
        var target = vulScores[vi.getValue('vulnerability')];
        if (!target) continue;

        vi.setValue('source_risk_score', target);
        vi.update();                                  // lets ServiceNow's calculators run

        var chk = new GlideRecord('sn_vul_vulnerable_item');
        chk.get(vi.getUniqueValue());
        var now = parseInt(chk.getValue('risk_score') || '0', 10);
        if (now < target) {
            chk.setValue('risk_score', target);
            chk.setValue('risk_rating', rating(target));
            chk.setWorkflow(false);                   // keep the calculator from resetting it
            chk.update();
            now = target;
            fixed++;
        } else {
            calculated++;
        }
        gs.print('ITEM   ' + chk.getValue('number') + '  risk ' + now + '  (' + chk.getDisplayValue('risk_rating') + ')');
    }
    gs.print('Done. ' + calculated + ' scored by ServiceNow, ' + fixed + ' set from CVSS.');
})();
