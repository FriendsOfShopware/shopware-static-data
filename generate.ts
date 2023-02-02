import { satisfies } from "https://github.com/omichelsen/compare-versions/raw/main/src/index.ts";

async function generate() {
    const allVersionsResp = await fetch('https://api.github.com/repos/shopware/platform/tags?per_page=100');
    const allVersions = await allVersionsResp.json();

    await generateSecurity(allVersions);
    await generatePHPVersionMap(allVersions);
}

async function generateSecurity(allVersions: any) {
    const storeAnswerResp = await fetch('https://api.shopware.com/pluginStore/pluginsByName?locale=en-GB&shopwareVersion=6.4.14.0&technicalNames%5B0%5D=SwagPlatformSecurity');
    const storeAnswer = await storeAnswerResp.json();

    const packagistResp = await fetch('https://packagist.org/api/security-advisories/?packages[]=shopware/platform');
    const packagist = await packagistResp.json();

    const data: Security = {
        latestPluginVersion: storeAnswer[0].version,
        advisories: {},
        versionToAdvisories: {},
    };

    for (const advisory of packagist.advisories['shopware/platform']) {
        data.advisories[advisory.advisoryId] = {
            title: advisory.title,
            link: advisory.link,
            cve: advisory.cve,
            affectedVersions: advisory.affectedVersions,
            source: advisory.source,
            reportedAt: advisory.reportedAt,
        };
    }


    for (let version of allVersions) {
        const versionName = version.name.replace(/^v/, '');

        for (let [id, advisory] of Object.entries(data.advisories)) {
            if (satisfies(versionName, advisory.affectedVersions)) {
                if (!data.versionToAdvisories[versionName]) {
                    data.versionToAdvisories[versionName] = [];
                }

                data.versionToAdvisories[versionName].push(id);
            }
        }
    }

    await Deno.writeTextFile("data/security.json", JSON.stringify(data, null, 4));
}

async function generatePHPVersionMap(allVersions: any) {
    const data: Record<string, string> = {};

    data['6.5.0.0'] = '8.1';

    for (let version of allVersions.reverse()) {
        const versionName = version.name.replace(/^v/, '');

        if (versionName.startsWith('6.5')) {
            data[versionName] = "8.1";
        } else if (versionName.startsWith('6.4')) {
            data[versionName] = "7.4";
        } else {
            data[versionName] = "7.2";
        }
    }

    await Deno.writeTextFile("data/php-version.json", JSON.stringify(data, null, 4));
}

generate().then();
