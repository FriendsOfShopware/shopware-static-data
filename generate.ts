import { satisfies } from "https://github.com/omichelsen/compare-versions/raw/main/src/index.ts";

interface ComposerPackageInfo {
    [key: string]: any;
}

/**
 * @todo: is there an API / simple way to dynamically load PHP minor versions? 
 */
const PHP_VERSIONS = [
    "7.0",
    "7.1",
    "7.2",
    "7.3",
    "7.4",
    "8.0",
    "8.1",
    "8.2",
];

async function generate() {
    const allVersionsResp = await fetch('https://api.github.com/repos/shopware/platform/tags?per_page=100');
    const allVersions = await allVersionsResp.json();

    await generateSecurity(allVersions);
    await generatePHPVersionMap(allVersions);
    await generateAllSupportedPhpVersions();
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

    data['6.5.0.0'] = '8.1';

    await Deno.writeTextFile("data/php-version.json", JSON.stringify(data, null, 4));
}

function expandPackagistVersions(versions: ComposerPackageInfo[]): ComposerPackageInfo[] {
    const expanded: ComposerPackageInfo[] = [];

    for (const versionData of versions) {
        const expandedVersion: ComposerPackageInfo = {};

        if (expanded.length > 0) {
            // Copy the previous expanded version to the current one
            Object.assign(expandedVersion, expanded[expanded.length - 1]);
        }

        for (const key in versionData) {
            const val = versionData[key];
            if (val === '__unset') {
                delete expandedVersion[key];
            } else {
                expandedVersion[key] = val;
            }
        }

        expanded.push(expandedVersion);
    }

    return expanded;
}


async function generateAllSupportedPhpVersions() {
    // TODO: typing for the API endpoint
    const packagistDataResp = await fetch("https://repo.packagist.org/p2/shopware/platform.json");
    const packagistData = await packagistDataResp.json();
    const packageVersions = expandPackagistVersions(packagistData.packages["shopware/platform"]);
    const data: Record<string, Array<string>> = {};

    for (let index in packageVersions) {
        const packageVersion = packageVersions[index];
        const semverVersion = packageVersion?.version;
        const phpDependency = packageVersion?.require?.php;

        if (!semverVersion || !phpDependency) {
            continue;
        }

        PHP_VERSIONS.forEach((phpVersion) => {
            if (satisfies(phpVersion, phpDependency)) {
                if (!data[semverVersion]) {
                    data[semverVersion] = [];
                }

                data[semverVersion].push(phpVersion);
            }
        });
    }

    await Deno.writeTextFile("data/all-supported-php-versions-by-shopware-version.json", JSON.stringify(data, null, 4));
}

generate().then();
