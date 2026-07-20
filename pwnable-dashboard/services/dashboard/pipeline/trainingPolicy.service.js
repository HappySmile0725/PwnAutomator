const path = require('path');

const paths = require('./paths');

const policy = require(path.join(paths.repoRoot, 'config', 'training-policy.json'));

const compileRegexes = (patterns, flags = 'i') => (patterns || []).map((pattern) => new RegExp(pattern, flags));

const matchesAnyRegex = (value, regexes) => {
    const text = String(value || '');
    return regexes.some((regex) => regex.test(text));
};

const runtimeRegexes = {
    flag: new RegExp(policy.runtimeValidation?.flagRegex || '$^', 'i'),
    commandIdentity: new RegExp(policy.runtimeValidation?.commandIdentityRegex || '$^', 'i'),
    strongSuccess: compileRegexes(policy.runtimeValidation?.strongSuccessRegex),
    weakSuccess: compileRegexes(policy.runtimeValidation?.weakSuccessRegex),
    unstable: compileRegexes(policy.runtimeValidation?.unstableRegex)
};

const payloadRegexes = {
    disallowed: compileRegexes(policy.payloadValidation?.disallowedRegex),
    wrapper: compileRegexes(policy.payloadValidation?.wrapperBoilerplateRegex || policy.payloadValidation?.wrapperBoilerplatePatterns)
};

const extractManagedPayloadBody = (source) => {
    const data = String(source || '').replace(/\r\n/g, '\n');
    const managedProcess = /^\s*p\s*=\s*process\((['"])\.\/[^'"]+\1\)\s*$/m.test(data);
    const managedRemote = /^\s*p\s*=\s*remote\(\s*os\.environ\[['"]PWN_AUTOMATOR_REMOTE_HOST['"]\]\s*,\s*int\(os\.environ\[['"]PWN_AUTOMATOR_REMOTE_PORT['"]\]\)\s*\)\s*$/m.test(data);
    if (!data.includes('p.interactive()') || (!managedProcess && !managedRemote)) {
        return data;
    }
    const lines = data.split('\n');
    let offset = 0;
    let start = -1;
    for (const line of lines) {
        offset += line.length + 1;
        if (/^\s*libc\s*=/.test(line)) {
            start = offset;
            break;
        }
        if (/^\s*e\s*=\s*ELF\(/.test(line)) {
            start = offset;
        }
    }
    const end = data.lastIndexOf('p.interactive()');
    return start >= 0 && end > start ? data.slice(start, end).trim() : data;
};

const definesUncalledExploitEntrypoint = (source) => {
    const text = String(source || '');
    if (!/^\s*def\s+exploit\s*\(/m.test(text)) {
        return false;
    }
    const withoutDefinitionLine = text.replace(/^\s*def\s+exploit\s*\([^\n]*\):\s*$/m, '');
    return !/^\s*exploit\s*\(/m.test(withoutDefinitionLine);
};

const payloadPolicyIssues = (source) => {
    const text = extractManagedPayloadBody(source);
    const validation = policy.payloadValidation || {};
    const issues = [];
    for (const regex of payloadRegexes.wrapper) if (regex.test(text)) issues.push(regex.source);
    for (const regex of payloadRegexes.disallowed) if (regex.test(text)) issues.push(regex.source);
    for (const pattern of validation.disallowedPatterns || []) {
        if (text.includes(pattern) && !issues.includes(pattern)) issues.push(pattern);
    }
    const maxSleepCalls = Number(validation.maxTimeSleepCalls || 1);
    if ((text.match(/\btime\.sleep\s*\(/g) || []).length > maxSleepCalls) issues.push('repeated time.sleep()');
    if (definesUncalledExploitEntrypoint(text)) issues.push('defined exploit() is not called');
    return issues;
};

module.exports = {
    definesUncalledExploitEntrypoint,
    extractManagedPayloadBody,
    policy,
    matchesAnyRegex,
    payloadPolicyIssues,
    payloadRegexes,
    runtimeRegexes
};
