import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { findAttackPaths, mergeGraphs, scanDirectory } from '../src/graph/attack-graph.ts';
import { parseIamPolicy, parseTerraform, parseWifWorkflow } from '../src/graph/gcp-iam-parser.ts';
import { buildBraceMap, closingBrace, createLineIndex, parseFirebaseRules, scanAllowClauses,
  stripComments, stripHclCommentsAndHeredocs } from '../src/graph/firebase-rules-parser.ts';
import { proposeRemediations } from '../src/report/remediation.ts';

const vulnerable = fileURLToPath(new URL('../fixtures/vulnerable-enterprise/', import.meta.url));
const hardened = fileURLToPath(new URL('../fixtures/hardened-enterprise/', import.meta.url));

test('line and brace indexes preserve offsets, escaped quotes and unmatched blocks', () => {
  const source = 'a\r\nb\nc\n', line = createLineIndex(source);
  assert.deepEqual(Array.from({ length: source.length + 1 }, (_, offset) => line(offset)), [1, 1, 1, 2, 2, 3, 3, 4]);
  const text = '{ "quoted": "\\\"}\\\"", \'single\': \'{\', nested: {} } unclosed {';
  const braces = buildBraceMap(text);
  assert.equal(braces.size, 2);
  assert.equal(braces.get(0), text.indexOf('} unclosed'));
  assert.equal(braces.get(text.indexOf('{}')), text.indexOf('{}') + 1);
  assert.equal(braces.has(text.length - 1), false);
});

test('dense parsers below 1 MiB stay within 350 ms and bounded heap', (t) => {
  const cases = [
    ['unclosed Firebase matches', 'parseFirebaseRules', 'match /a{'.repeat(80_000), 80_001],
    ['Firebase scope sweep', 'parseFirebaseRules', 'service cloud.firestore { ' + 'match /a{allow get;}'.repeat(40_000) + '}', 40_000],
    ['Firebase duplicate edge accumulation', 'scanDirectory', 'service cloud.firestore { match /a {\n'
      + 'allow get,create;\n'.repeat(50_000) + '}}', 100_000],
    ['Firebase nesting limit', 'parseFirebaseRules', 'service cloud.firestore { '
      + 'match /a{allow get;'.repeat(25_000) + '}'.repeat(25_001), 65],
    ['Terraform resource lines', 'parseTerraform', 'resource "a" "b"{}\n'.repeat(45_000), 0],
    ['Terraform attribute depth', 'parseTerraform', 'resource "google_project_iam_member" "grant" {\n'
      + 'nested { role = "roles/owner" }\n'.repeat(25_000)
      + 'role = "roles/secretmanager.secretAccessor"\nmember = "allUsers"\n}', 1],
    ['Terraform correlation resource index', 'scanDirectory', 'resource "a" "b"{}\n'.repeat(45_000), 0],
    ['Terraform nested resource headers', 'scanDirectory', 'resource "google_cloud_run_v2_service" "a" {'.repeat(18_000)
      + '}'.repeat(18_000), 0],
    ['WIF blank-line scaling', 'parseWifWorkflow', Array.from({ length: 1000 }, (_, i) => ' '.repeat(i % 40) + '- a').join('\n')
      + '\n'.repeat(500_000), 0],
    ['WIF comment scaling', 'parseWifWorkflow', Array.from({ length: 400 }, () => '    - uses: google-github-actions/auth@v3\n'
      + '      with:\n        workload_identity_provider: projects/1/locations/global/workloadIdentityPools/p/providers/pr\n'
      + '        service_account: sa@p.iam.gserviceaccount.com').join('\n') + '\n' + '# comment line\n'.repeat(40_000), 0],
    ['Cloud Run runtime correlation', 'scanDirectory', Array.from({ length: 8_000 }, (_, index) =>
      `resource "google_cloud_run_v2_service" "s${index}" {template {service_account="a@p.gserviceaccount.com"}}\n`).join(''), 0],
    ['Cloud Run inferred runtime correlation', 'scanDirectory', Array.from({ length: 8_000 }, (_, index) =>
      `resource "google_cloud_run_v2_service" "s${index}" {name="s${index}" project="1" location="r"}\n`).join(''), 0],
    ['IAM escaped role search', 'parseIamPolicy', '{"bindings":['
      + Array(14_000).fill('{"role":"roles\\u002fviewer","members":[]}').join(',') + ']}', 0],
    ['IAM resource amplification', 'parseIamPolicy', JSON.stringify({ resource: 'projects/' + 'a'.repeat(500_000),
      bindings: [{ role: 'roles/viewer', members: Array(10_000).fill('allUsers') }] }), 1],
  ] as const;
  for (const [label, parser, source, expectedFindings] of cases) {
    assert.ok(Buffer.byteLength(source) < 1024 * 1024, label);
    const script = `import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
      import { tmpdir } from 'node:os';
      import { join } from 'node:path';
      import { parseIamPolicy, parseTerraform, parseWifWorkflow } from ${JSON.stringify(new URL('../src/graph/gcp-iam-parser.ts', import.meta.url).href)};
      import { parseFirebaseRules } from ${JSON.stringify(new URL('../src/graph/firebase-rules-parser.ts', import.meta.url).href)};
      import { scanDirectory } from ${JSON.stringify(new URL('../src/graph/attack-graph.ts', import.meta.url).href)};
      const source = readFileSync(0, 'utf8');
      const directory = ${parser === 'scanDirectory'} ? mkdtempSync(join(tmpdir(), 'atlas-gcp-complexity-')) : undefined;
      try {
        if (directory) writeFileSync(join(directory, ${JSON.stringify(label.startsWith('Firebase') ? 'dense.firestore.rules.sample' : 'main.tf')}), source);
        const start = performance.now();
        const graph = ${parser === 'scanDirectory' ? 'scanDirectory(directory)' : `${parser}(source, 'dense.fixture')`};
        console.log(JSON.stringify({ elapsed: performance.now() - start, findings: graph.findings.length,
          diagnostics: [...new Set(graph.findings.filter(item => item.ruleId.startsWith('scan/'))
            .map(item => item.ruleId + ':' + item.severity))],
          diagnosticCount: graph.findings.filter(item => item.ruleId.startsWith('scan/')).length,
          edges: graph.edges.length, resources: graph.nodes.filter(node => node.kind === 'resource').length,
          edgeFindingIds: ${label === 'Firebase duplicate edge accumulation'} ? graph.edges.map(edge => edge.findingIds.length) : [],
          limitations: graph.limitations.length, evidence: graph.findings.length === 1 ? graph.findings[0].evidence : '' }));
      } finally { if (directory) rmSync(directory, { recursive: true, force: true }); }`;
    const result = spawnSync(process.execPath, ['--max-old-space-size=256', '--input-type=module', '-e', script], {
      input: source, encoding: 'utf8', timeout: 10_000, maxBuffer: 16_384,
      env: { PATH: process.env.PATH, LANG: 'C' },
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, `${label}: ${result.stderr}`);
    const measurement = JSON.parse(result.stdout);
    assert.equal(measurement.findings, expectedFindings, label);
    if (label === 'Firebase duplicate edge accumulation') {
      assert.equal(measurement.edges, 2);
      assert.deepEqual(measurement.edgeFindingIds, [100_000, 100_000]);
    }
    if (label === 'Terraform attribute depth') assert.match(measurement.evidence, /roles\/secretmanager.secretAccessor/);
    if (label === 'Firebase nesting limit') {
      assert.deepEqual(measurement.diagnostics, ['scan/traversal-limit:high']);
      assert.equal(measurement.diagnosticCount, 1);
      assert.equal(measurement.edges, 128);
    }
    if (label.startsWith('Cloud Run')) assert.equal(measurement.edges, 8_000);
    if (label === 'Terraform nested resource headers') {
      assert.equal(measurement.resources, 1);
    }
    if (label === 'WIF blank-line scaling') assert.equal(measurement.edges, 0);
    if (label === 'WIF comment scaling') assert.equal(measurement.edges, 400);
    if (label === 'IAM resource amplification') {
      assert.deepEqual(measurement.diagnostics, ['scan/invalid-input:high']);
      assert.equal(measurement.diagnosticCount, 1);
      assert.equal(measurement.edges, 0);
    }
    assert.ok(measurement.elapsed < 350, `${label}: ${measurement.elapsed} ms`);
    t.diagnostic(`${label}: ${Buffer.byteLength(source)} bytes, ${measurement.elapsed.toFixed(2)} ms (< 350 ms; 256 MiB heap cap)`);
  }
});

test('Firebase scope limits preserve boundary grants, recursive ancestry and sibling recovery', () => {
  const file = 'limits.firestore.rules.sample';
  for (const depth of [64, 65]) {
    const source = 'service cloud.firestore { ' + 'match /a{'.repeat(depth) + 'allow get;'
      + '}'.repeat(depth) + 'match /sibling { allow get; }}';
    const graph = parseFirebaseRules(source, file);
    assert.equal(graph.findings.filter(item => item.ruleId === 'scan/traversal-limit').length, depth === 65 ? 1 : 0);
    assert.equal(graph.findings.filter(item => item.ruleId === 'firebase/public-read').length, depth === 65 ? 1 : 2);
    assert.ok(graph.nodes.some(node => node.label === 'firestore data matching /sibling'));
  }
  const emptyDeep = parseFirebaseRules('service cloud.firestore { ' + 'match /a{'.repeat(65) + '}'.repeat(66), file);
  assert.deepEqual(emptyDeep.findings.map(item => item.ruleId), ['scan/traversal-limit']);
  for (const length of [4096, 4097]) {
    const path = '/' + 'a'.repeat(length - 1);
    const graph = parseFirebaseRules(`service cloud.firestore { match ${path} { allow get; }
      match /other${path} { allow get; } match /sibling { allow get; } }`, file);
    assert.equal(graph.findings.filter(item => item.ruleId === 'scan/traversal-limit').length, 1);
    assert.equal(graph.nodes.some(node => node.label === `firestore data matching ${path}`), length === 4096);
    assert.ok(graph.nodes.some(node => node.label === 'firestore data matching /sibling'));
    const joined = parseFirebaseRules(`service cloud.firestore { match /a { match ${path} { allow get; } } }`, file);
    assert.deepEqual(joined.findings.map(item => item.ruleId), ['scan/traversal-limit']);
  }
  const recursive = parseFirebaseRules(`service cloud.firestore { match /{doc=**} { match /child { allow get; } }
    match /ordinary { allow get; } }`, file);
  assert.equal(recursive.findings.filter(item => item.ruleId === 'firebase/recursive-wildcard').length, 1);
});

test('IAM resource and name limits reject oversized input before expanding any grants', () => {
  const bindings = [{ role: 'roles/viewer', members: ['allUsers'] }];
  for (const field of ['resource', 'name']) {
    for (const length of [2048, 2049, 5009]) {
      const graph = parseIamPolicy(JSON.stringify({ [field]: 'projects/' + 'a'.repeat(length - 9), bindings }), 'iam.json');
      assert.equal(graph.findings.some(item => item.ruleId === 'scan/invalid-input'), length > 2048);
      assert.equal(graph.edges.length, length > 2048 ? 0 : 1);
    }
  }
  const graph = parseIamPolicy(JSON.stringify({ resource: 'projects/valid', name: 'a'.repeat(2049), bindings }), 'iam.json');
  assert.deepEqual(graph.findings.map(item => item.ruleId), ['scan/invalid-input']);
  assert.deepEqual(graph.nodes, []);
});

test('IAM JSON discovery uses token and camelCase boundaries instead of word substrings', () => {
  const directory = mkdtempSync(join(tmpdir(), 'atlas-gcp-iam-'));
  const ignored = ['diamond.json', 'parliament.json', 'mediamap.json', 'william.json', 'ciam.json', 'projectiam.json', 'iamish.json'];
  const scanned = ['iam.json', 'iam-policy.json', 'iam_bindings.json', 'project.iam.json', 'project_iam.json',
    'iamPolicy.json', 'serviceIamPolicy.json', 'IAM.json', 'project.Iam.json', 'serviceIAMPolicy.json'];
  try {
    for (const file of ignored) writeFileSync(join(directory, file), '{}');
    assert.deepEqual(scanDirectory(directory).findings, []);
    for (const file of scanned) {
      writeFileSync(join(directory, file), '{}');
      const findings = scanDirectory(directory).findings;
      assert.deepEqual(findings.map(item => [item.ruleId, item.location.file]), [['scan/invalid-input', file]]);
      rmSync(join(directory, file));
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('many remediation findings in one file stay within 350 ms and bounded heap', (t) => {
  const source = 'service cloud.firestore { match /a {\n' + 'allow get; // retained comment\n'.repeat(8_000) + '} }';
  assert.ok(Buffer.byteLength(source) < 1024 * 1024);
  const script = `import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
    import { tmpdir } from 'node:os';
    import { join } from 'node:path';
    import { parseFirebaseRules } from ${JSON.stringify(new URL('../src/graph/firebase-rules-parser.ts', import.meta.url).href)};
    import { proposeRemediations } from ${JSON.stringify(new URL('../src/report/remediation.ts', import.meta.url).href)};
    const directory = mkdtempSync(join(tmpdir(), 'atlas-gcp-remediation-'));
    const file = 'dense.firestore.rules.sample', source = readFileSync(0, 'utf8');
    try {
      writeFileSync(join(directory, file), source);
      const graph = parseFirebaseRules(source, file);
      const start = performance.now();
      const proposals = proposeRemediations(graph.findings, directory);
      const elapsed = performance.now() - start;
      console.log(JSON.stringify({ elapsed, count: proposals.length, patches: proposals.filter(item =>
        item.diff.includes('+allow get: if false; // retained comment')).length,
        unchanged: readFileSync(join(directory, file), 'utf8') === source }));
    } finally { rmSync(directory, { recursive: true, force: true }); }`;
  const result = spawnSync(process.execPath, ['--max-old-space-size=256', '--input-type=module', '-e', script], {
    input: source, encoding: 'utf8', timeout: 10_000, maxBuffer: 16_384,
    env: { PATH: process.env.PATH, LANG: 'C' },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  const measurement = JSON.parse(result.stdout);
  assert.equal(measurement.count, 8_000);
  assert.equal(measurement.patches, 8_000);
  assert.equal(measurement.unchanged, true);
  assert.ok(measurement.elapsed < 350, `${measurement.elapsed} ms`);
  t.diagnostic(`${Buffer.byteLength(source)} bytes: ${measurement.elapsed.toFixed(2)} ms (< 350 ms; 256 MiB heap cap)`);
});

test('Firebase compact if and allow property references preserve findings and safe diffs', () => {
  const directory = mkdtempSync(join(tmpdir(), 'atlas-gcp-rules-'));
  const file = 'compact.firestore.rules.sample';
  const source = `service cloud.firestore {
  match /users/{uid} {
    allow read, write: if(true); allow get: if ( true ); allow list: if t r u e; // allow delete: if(true);
    allow write: if request.auth != null && request.resource.data.allow == true;
    allow update: if!(false) && request.auth != null;
    allow read: if request.resource.data.allow == true;
    allow read: if 'allow write: if(true);' == 'text'; allow list: if false;
    allow read: iftrue;
  }
  match /private/{id} { allow read: if false; }
}\n`;
  try {
    writeFileSync(join(directory, file), source);
    const graph = scanDirectory(directory);
    assert.deepEqual(graph.findings.filter(item => item.ruleId.startsWith('firebase/public-'))
      .map(item => item.ruleId).sort(), ['firebase/public-read', 'firebase/public-read', 'firebase/public-write']);
    assert.deepEqual(graph.findings.filter(item => item.ruleId === 'firebase/privilege-fields')
      .map(item => item.location.line).sort(), [4, 5]);
    const diffs = proposeRemediations(graph.findings, directory).filter(item => item.diff);
    assert.equal(diffs.length, 1);
    assert.ok(diffs[0].diff.includes('+    allow read, write: if(false); allow get: if ( false ); allow list: if t r u e; // allow delete: if(true);'));
    assert.equal(readFileSync(join(directory, file), 'utf8'), source);
    assert.deepEqual([...scanAllowClauses('allow read: if!(false);')].map(item => item.condition), ['!(false)']);
    assert.deepEqual([...scanAllowClauses('x.allow read: if true; data. /*masked*/ allow read: if true;')], []);
    const recovered = parseFirebaseRules('service cloud.firestore { match /a { allow get: if x } match /b { allow get; } }', file);
    assert.equal(recovered.findings.filter(item => item.ruleId === 'firebase/public-read').length, 1);
    assert.ok(recovered.nodes.some(node => node.label === 'firestore data matching /b'));
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('IAM null conditions are unconditional, malformed conditions fail closed and repeated roles retain lines', () => {
  const source = `{
  "resource": "projects/fixture-project",
  "bindings": [
    {"role":"roles/secretmanager.secretAccessor","members":["allUsers"],"condition":null},
    {"role":"roles/secretmanager.secretAccessor","members":["allAuthenticatedUsers"]},
    {"role":"roles/secretmanager.secretAccessor","members":["user:fixture@example.invalid"],"condition":{}}
  ]
}`;
  const graph = parseIamPolicy(source, 'iam-policy.json');
  assert.deepEqual(graph.edges.map(edge => edge.confidence), ['confirmed', 'confirmed', 'potential']);
  assert.deepEqual(graph.findings.map(item => item.location.line), [4, 5]);
  assert.deepEqual(graph.nodes.filter(node => node.kind !== 'data').map(node => node.location?.line), [4, 5, 6]);
  for (const condition of ['invalid', [], 0, false]) {
    const invalid = parseIamPolicy(JSON.stringify({ bindings: [{ role: 'roles/viewer', members: ['allUsers'], condition }] }), 'iam-policy.json');
    assert.ok(invalid.findings.some(item => item.ruleId === 'scan/invalid-input'));
    assert.deepEqual(invalid.edges, []);
  }
});

test('Cloud Run v2 IAM name references and literal bindings reach runtime secrets', () => {
  const directory = mkdtempSync(join(tmpdir(), 'atlas-gcp-terraform-'));
  const account = 'worker@fixture-project.iam.gserviceaccount.com';
  try {
    writeFileSync(join(directory, 'identity.tf'), `resource "google_project_iam_member" "secrets" {
      project = "fixture-project"
      role = "roles/secretmanager.secretAccessor"
      member = "serviceAccount:${account}"
    }`);
    for (const kind of ['member', 'binding']) {
      for (const name of ['google_cloud_run_v2_service.api.name', '"api"']) {
        const source = `resource "google_cloud_run_v2_service" "api" {
          name = "api"
          project = "fixture-project"
          location = "us-central1"
          template { service_account = "${account}" }
        }
        resource "google_cloud_run_v2_service_iam_${kind}" "public" {
          name = ${name}
          project = "fixture-project"
          location = "us-central1"
          role = "roles/run.invoker"
          ${kind === 'member' ? 'member = "allUsers"' : 'members = ["allUsers"]'}
        }`;
        writeFileSync(join(directory, 'main.tf'), source);
        const graph = scanDirectory(directory);
        const path = graph.paths.find(path => path.nodes[0] === 'entry:iam:allUsers' && path.description.includes('Secret Manager'));
        assert.ok(path, `${kind}: ${name}`);
        assert.deepEqual(path.nodes.slice(0, 3), ['entry:iam:allUsers', 'tf:.:google_cloud_run_v2_service.api', `identity:${account}`]);
        assert.equal(path.nodes.length, 4);
        assert.equal(path.confidence, 'potential');
        if (name === '"api"') {
          writeFileSync(join(directory, 'main.tf'), source.replace('name = "api"\n          project = "fixture-project"\n          location = "us-central1"\n          role',
            'name = "api"\n          project = "other-project"\n          location = "us-central1"\n          role'));
          assert.equal(scanDirectory(directory).paths.some(path => path.nodes[0] === 'entry:iam:allUsers' && path.description.includes('Secret Manager')), false);
        }
      }
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('literal IAM grants preserve both Cloud Run services and the second runtime secret path', () => {
  const directory = mkdtempSync(join(tmpdir(), 'atlas-gcp-terraform-'));
  const account = 'privileged@fixture-project.iam.gserviceaccount.com';
  const services = ['tf:.:google_cloud_run_v2_service.svc1', 'tf:.:google_cloud_run_v2_service.svc2'];
  const source = `resource "google_cloud_run_v2_service" "svc1" {
  name = "svc1" project = "fixture-project" location = "us-central1"
  template { service_account = "unprivileged@fixture-project.iam.gserviceaccount.com" }
}
resource "google_cloud_run_v2_service" "svc2" {
  name = "svc2" project = "fixture-project" location = "us-central1"
  template { service_account = "${account}" }
}
resource "google_project_iam_member" "secrets" {
  project = "fixture-project" role = "roles/secretmanager.secretAccessor" member = "serviceAccount:${account}"
}
${['svc1', 'svc2'].map(name => `resource "google_cloud_run_v2_service_iam_member" "${name}" {
  name = "${name}" project = "fixture-project" location = "us-central1"
  role = "roles/run.invoker" member = "allUsers"
}`).join('\n')}`;
  try {
    writeFileSync(join(directory, 'main.tf'), source);
    const graph = scanDirectory(directory);
    assert.deepEqual(services.map(id => graph.nodes.find(node => node.id === id)?.location?.line), [1, 5]);
    assert.deepEqual(graph.edges.filter(edge => edge.from === 'entry:iam:allUsers' && edge.kind === 'iam-grant')
      .map(edge => edge.to).sort(), services);
    const paths = graph.paths.filter(path => path.nodes[0] === 'entry:iam:allUsers' && path.description.includes('Secret Manager'));
    assert.equal(paths.length, 1);
    assert.deepEqual(paths[0].nodes, ['entry:iam:allUsers', services[1], `identity:${account}`,
      'data:project:fixture-project:Secret Manager secrets']);
    assert.equal(paths[0].confidence, 'potential');
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('literal and unresolved service IAM scopes never collapse to project scope', () => {
  for (const [type, field, family] of [
    ['google_cloud_run_service', 'service', 'services'],
    ['google_cloud_run_v2_service', 'name', 'services'],
    ['google_cloudfunctions_function', 'cloud_function', 'functions'],
    ['google_cloudfunctions2_function', 'cloud_function', 'functions'],
  ]) {
    for (const kind of ['member', 'binding']) {
      for (const region of ['region = "us-central1"', '']) {
        const source = ['svc1', 'svc2'].map(name => `resource "${type}_iam_${kind}" "${name}" {
          ${field} = "${name}" project = "fixture-project" ${region}
          role = "roles/${family === 'services' ? 'run' : 'cloudfunctions'}.invoker"
          ${kind === 'member' ? 'member = "allUsers"' : 'members = ["allUsers"]'}
        }`).join('\n');
        const graph = mergeGraphs([parseTerraform(source, 'main.tf')]);
        assert.deepEqual(graph.edges.map(edge => edge.to).sort(), ['svc1', 'svc2'].map(name => region
          ? `resource:projects/fixture-project/locations/us-central1/${family}/${name}`
          : `resource:tf:.:${type}_iam_${kind}.${name}:unresolved-resource`));
      }
    }
  }
});

test('indexed correlation preserves service scope, aliases, non-invoker isolation and runtime blocks', () => {
  const directory = mkdtempSync(join(tmpdir(), 'atlas-gcp-correlation-'));
  const file = 'services:9:identity:principal.tf';
  const runtime = 'runtime@p.gserviceaccount.com';
  const source = `resource "google_cloud_run_v2_service" "east" {
    name="api" project="p" location="east" template {service_account="${runtime}"}
  }
  resource "google_cloud_run_v2_service" "west" {
    name="api" project="p" location="west" template {service_account="${runtime}"}
  }
  resource "google_cloudfunctions2_function" "east" {
    name="api" project="p" location="east"
    build_config {service_account="build@p.gserviceaccount.com"}
    service_config {service_account_email="${runtime}"}
  }
  resource "google_cloud_run_v2_service_iam_member" "invoke" {
    name="api" project="p" location="east" role="roles/run.invoker" member="user:run@example.invalid"
  }
  resource "google_cloudfunctions2_function_iam_member" "invoke" {
    cloud_function="api" project="p" location="east" role="roles/cloudfunctions.invoker" member="user:function@example.invalid"
  }
  resource "google_cloud_run_v2_service_iam_member" "inspect" {
    name=google_cloud_run_v2_service.east.name role="roles/run.viewer" member="allUsers"
  }`;
  const east = 'tf:.:google_cloud_run_v2_service.east', west = 'tf:.:google_cloud_run_v2_service.west';
  const functions = 'tf:.:google_cloudfunctions2_function.east';
  try {
    writeFileSync(join(directory, file), source);
    for (const [index, prefix] of ['', '//run.googleapis.com/'].entries()) {
      writeFileSync(join(directory, `alias-${index}-iam.json`), JSON.stringify({
        resource: `${prefix}projects/p/locations/west/services/api`,
        bindings: [{ role: 'roles/run.invoker', members: [`user:alias${index}@example.invalid`] }],
      }));
    }
    const graph = scanDirectory(directory);
    const grantTo = (member: string) => graph.edges.filter(edge => edge.kind === 'iam-grant' && edge.evidence.startsWith(`${member} -> `))
      .map(edge => edge.to);
    assert.deepEqual(grantTo('user:run@example.invalid'), [east]);
    assert.deepEqual(grantTo('user:function@example.invalid'), [functions]);
    assert.deepEqual(grantTo('allUsers'), [`resource:${east}:non-invocation`]);
    for (const index of [0, 1]) assert.deepEqual(grantTo(`user:alias${index}@example.invalid`), [west]);
    assert.deepEqual(graph.edges.filter(edge => edge.from === functions && edge.kind === 'potential-runtime-identity-access')
      .map(edge => edge.to), [`identity:${runtime}`]);
    assert.equal(graph.paths.some(path => path.nodes[0] === 'entry:iam:allUsers'), false);
    writeFileSync(join(directory, file), source + '\n' + `resource "google_cloud_run_v2_service" "duplicate" {
      name="api" project="p" location="east" template {service_account="${runtime}"}
    }`);
    const ambiguous = scanDirectory(directory);
    assert.equal(ambiguous.edges.some(edge => edge.from === 'identity:user:run@example.invalid' && edge.to === east), false);
    assert.equal(ambiguous.edges.some(edge => edge.from === 'identity:user:function@example.invalid' && edge.to === functions), true);
    writeFileSync(join(directory, file), `resource "google_cloud_run_v2_service" "control" {
      name="api" project="p" location="east\\u0000x"
    }
    resource "google_cloud_run_v2_service_iam_member" "control" {
      name="x\\u0000api" project="p" location="east" role="roles/run.invoker" member="allUsers"
    }`);
    assert.equal(scanDirectory(directory).edges.some(edge => edge.kind === 'iam-grant'
      && edge.to === 'tf:.:google_cloud_run_v2_service.control'), false, 'Composite keys must preserve exact tuple equality');
    for (const last of ['template {service_account="last@p.gserviceaccount.com"}', '']) {
      writeFileSync(join(directory, file), `resource "google_cloud_run_v2_service" "duplicate" {
        template {service_account="first@p.gserviceaccount.com"}
      }
      resource "google_cloud_run_v2_service" "duplicate" {${last}}`);
      assert.deepEqual(scanDirectory(directory).edges.filter(edge => edge.kind === 'potential-runtime-identity-access')
        .map(edge => edge.to), last ? ['identity:last@p.gserviceaccount.com'] : []);
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('finding and edge deduplication remain deterministic without changing input graphs', () => {
  const graph = parseFirebaseRules('service cloud.firestore { match /a { allow get; } }', 'fixture.firestore.rules.sample');
  const alternate = { ...graph, findings: graph.findings.map(item => ({ ...item, message: 'alternate evidence description' })),
    edges: graph.edges.map(edge => ({ ...edge, id: 'z' + edge.id, findingIds: ['extra', 'extra', ...edge.findingIds] })) };
  const before = JSON.stringify([graph, alternate]);
  assert.deepEqual(mergeGraphs([graph, alternate]), mergeGraphs([alternate, graph]));
  assert.equal(mergeGraphs([graph, alternate]).findings.length, 1);
  for (const edge of mergeGraphs([graph, alternate]).edges) {
    const original = graph.edges.find(item => item.id === edge.id);
    assert.ok(original, 'The smallest edge id must survive');
    assert.deepEqual(edge.findingIds, [...original.findingIds, 'extra'].sort());
  }
  assert.equal(JSON.stringify([graph, alternate]), before);

  const merged = mergeGraphs([graph, alternate, graph]);
  const expectedFinding = [graph.findings[0], alternate.findings[0]]
    .sort((a, b) => JSON.stringify(a) < JSON.stringify(b) ? -1 : 1).at(-1);
  assert.deepEqual(merged.findings, [expectedFinding]);
  const node = graph.nodes.find(node => node.location)!;
  const columns = [2, 10].map(column => ({ ...node, location: { ...node.location!, column } }));
  const located = { ...graph, nodes: [columns[0], { ...node, location: undefined }, columns[1], { ...columns[1] }] };
  assert.deepEqual(mergeGraphs([located]).nodes, [columns[1]]);
  assert.deepEqual(mergeGraphs([located]).nodes, mergeGraphs([{ ...located, nodes: [...located.nodes].reverse() }]).nodes);

  const edge = graph.edges[0];
  const distinctEdges = [
    { ...edge, id: 'a', from: 'a\0b', to: 'c|d' },
    { ...edge, id: 'b', from: 'a', to: 'b\0c|d' },
    { ...edge, id: 'c', from: 'a|b', to: 'c' },
    { ...edge, id: 'd', from: 'a', to: 'b|c' },
    { ...edge, id: 'e', kind: 'grant|confirmed', confidence: 'potential' as const, evidence: 'tail\0|' },
    { ...edge, id: 'f', kind: 'grant', confidence: 'confirmed' as const, evidence: 'potential|tail\0|' },
  ];
  const delimited = { ...graph, edges: distinctEdges };
  assert.deepEqual(mergeGraphs([delimited]).edges, distinctEdges);
  assert.deepEqual(mergeGraphs([delimited]), mergeGraphs([{ ...delimited, edges: [...distinctEdges].reverse() }]));
  const unknown = { ...edge, findingIds: ['unknown'] };
  assert.deepEqual(mergeGraphs([{ ...graph, edges: [unknown] }]).edges[0].findingIds, ['unknown']);
  assert.notEqual(merged.edges[0].findingIds, merged.edges[1].findingIds);
  assert.equal(findAttackPaths({ ...graph, findings: [] })[0].severity, 'medium');

  const repeated = parseFirebaseRules('service cloud.firestore { match /users/{uid} {\n'
    + 'allow get,create;\n'.repeat(100) + 'allow update: if request.auth != null; }}', 'dense.firestore.rules.sample');
  assert.equal(repeated.nodes.length, 4);
  assert.equal(new Set(repeated.nodes.map(node => node.id)).size, 4);
  assert.equal(repeated.nodes.find(node => node.kind === 'resource')?.location?.line, 100);
  assert.equal(repeated.nodes.find(node => node.kind === 'data')?.label, 'Potential privilege fields at /users/{uid}');
  assert.equal(repeated.nodes.find(node => node.kind === 'data')?.location?.line, 102);
  assert.equal(repeated.findings.length, 201);
  assert.equal(repeated.edges.length, 201);
});

test('Terraform attributes ignore nested and quoted decoys while retaining exact source offsets', () => {
  const graph = parseTerraform(`resource "google_project_iam_member" "reader" {
    note = "role = \\"roles/owner\\" member = \\"allUsers\\""
    nested { role = "roles/editor" member = "allUsers" }
    role = "roles/secretmanager.secretAccessor"
    member = "user:fixture@example.invalid"
  }
  resource "google_cloud_run_v2_service" "api" {
    template { service_account = "runtime@fixture-project.iam.gserviceaccount.com" }
    ingress = "INGRESS_TRAFFIC_ALL"
  }`, 'main.tf');
  assert.equal(graph.edges.filter(edge => edge.kind === 'iam-grant').length, 1);
  assert.match(graph.edges.find(edge => edge.kind === 'iam-grant')!.evidence, /^user:fixture@example.invalid -> roles\/secretmanager.secretAccessor/);
  assert.equal(graph.findings.find(item => item.ruleId === 'gcp/public-ingress')?.location.line, 9);
});

test('enterprise scan finds Firebase, public services, IAM escalation and unpinned WIF', () => {
  const graph = scanDirectory(vulnerable);
  const rules = new Set(graph.findings.map(finding => finding.ruleId));
  for (const rule of ['firebase/public-read', 'firebase/public-write', 'firebase/recursive-wildcard',
    'firebase/privilege-fields', 'gcp/public-service', 'gcp/public-ingress',
    'iam/default-service-account', 'iam/privilege-escalation', 'wif/unpinned-provider']) {
    assert.ok(rules.has(rule), `Missing ${rule}`);
  }
  assert.ok(graph.findings.some(finding => finding.ruleId === 'firebase/public-write'
    && finding.location.file === 'vulnerable.storage.rules.sample'));
  assert.ok(!graph.findings.some(finding => finding.ruleId.startsWith('scan/')));
  assert.deepEqual(scanDirectory(vulnerable), graph, 'Repeat scans must be deterministic');
});

test('paths connect public Cloud Run through runtime identity and impersonation to secrets', () => {
  const graph = scanDirectory(vulnerable);
  const path = graph.paths.find(candidate => candidate.nodes[0] === 'entry:iam:allUsers'
    && candidate.edges.length >= 4 && candidate.description.includes('Secret Manager'));
  assert.ok(path, 'Expected a multi-hop cross-boundary path');
  assert.equal(path.confidence, 'potential', 'Runtime compromise is not proven by configuration');
  assert.equal(path.nodes.length, path.edges.length + 1);
  const edges = new Map(graph.edges.map(edge => [edge.id, edge]));
  path.edges.forEach((id, index) => {
    assert.equal(edges.get(id)?.from, path.nodes[index]);
    assert.equal(edges.get(id)?.to, path.nodes[index + 1]);
  });
  assert.ok(path.edges.some(id => edges.get(id)?.kind === 'service-account-impersonation'));
  assert.ok(graph.findings.some(finding => path.findingIds.includes(finding.id)
    && finding.ruleId === 'iam/privilege-escalation'));
});

test('remediation proposals contain review-only diffs and preserve all scanned files', () => {
  const snapshot = () => readdirSync(vulnerable).sort().map(name => [name, readFileSync(join(vulnerable, name), 'utf8')]);
  const before = snapshot();
  const graph = scanDirectory(vulnerable);
  const proposals = proposeRemediations(graph.findings, vulnerable);
  assert.ok(proposals.length > 0);
  assert.ok(proposals.every(proposal => proposal.automatic === false
    && graph.findings.some(finding => finding.id === proposal.findingId)));
  const patches = proposals.filter(proposal => proposal.diff);
  assert.ok(patches.some(proposal => proposal.file === 'vulnerable.storage.rules.sample'));
  for (const proposal of patches) {
    assert.match(proposal.diff, /^--- .*\n\+\+\+ .*\n@@ /);
  }
  assert.ok(patches.some(proposal => /\+.*if false;/.test(proposal.diff)));
  const terraform = readFileSync(join(vulnerable, 'main.tf'), 'utf8').split('\n');
  for (const [attribute, original, replacement] of [
    ['ingress', 'INGRESS_TRAFFIC_ALL', 'INGRESS_TRAFFIC_INTERNAL_ONLY'],
    ['ingress_settings', 'ALLOW_ALL', 'ALLOW_INTERNAL_ONLY'],
  ]) {
    const line = terraform.findIndex(text => new RegExp(`^\\s*${attribute}\\s*=`).test(text)) + 1;
    assert.ok(line > 1);
    const finding = graph.findings.find(item => item.ruleId === 'gcp/public-ingress'
      && item.location.file === 'main.tf' && item.evidence.includes(original));
    assert.ok(finding);
    assert.equal(finding.location.line, line);
    const proposal = patches.find(item => item.findingId === finding.id);
    assert.ok(proposal, `Missing ${original} ingress diff`);
    assert.ok(proposal.diff.includes(`@@ -${line},1 +${line},1 @@`));
    assert.ok(proposal.diff.includes(`-${terraform[line - 1]}\n+${terraform[line - 1].replace(original, replacement)}\n`));
  }
  assert.deepEqual(snapshot(), before);
});

test('adversarial parser inputs stay below the 200 ms runtime budget', (t) => {
  const firestore = 'service cloud.firestore { match /databases/{d}/documents { ';
  const malformedAccount = '/serviceAccounts/' + '@'.repeat(50_000) + '/';
  const cases = [
    ['unclosed Terraform members', 'parseTerraform',
      'resource "google_project_iam_binding" "b" { role = "roles/viewer" members = [' + '"a",'.repeat(40) + ' }'],
    ['Firebase trailing whitespace', 'parseFirebaseRules', firestore + 'allow read: if ' + ' '.repeat(20_000) + '}}'],
    ['Firebase stripped comments', 'parseFirebaseRules', firestore + 'allow read: if /*' + ' '.repeat(20_000) + '*/}}'],
    ['Firebase repeated unclosed clauses', 'parseFirebaseRules', 'allow read: if x\n'.repeat(5_000)],
    ['Firebase repeated clauses inside a match', 'parseFirebaseRules', firestore + 'allow read: if x\n'.repeat(5_000) + '}}'],
    ['Firebase parenthesized header keywords before map brace', 'parseFirebaseRules',
      'service cloud.firestore { match /a { allow read: if (' + 'match '.repeat(80_000) + '{).x {} } }'],
    ['Firebase escaped quotes and newline before map brace', 'parseFirebaseRules',
      'service cloud.firestore { match /a { allow read: if ["' + '\\"'.repeat(100_000) + '\\\n", {}] == []; } }'],
    ['IAM repeated account separators', 'parseIamPolicy', JSON.stringify({ resource: malformedAccount, bindings: [] })],
    ['Terraform repeated account separators', 'parseTerraform',
      `resource "google_service_account_iam_member" "b" { service_account_id = "${malformedAccount}" role = "roles/iam.workloadIdentityUser" member = "user:fixture@example.invalid" }`],
  ];
  for (const [label, parser, source] of cases) {
    // A subprocess deadline also stops a regressed synchronous regex that would block node:test.
    const script = `import { performance } from 'node:perf_hooks';
      import { parseTerraform, parseIamPolicy } from ${JSON.stringify(new URL('../src/graph/gcp-iam-parser.ts', import.meta.url).href)};
      import { parseFirebaseRules } from ${JSON.stringify(new URL('../src/graph/firebase-rules-parser.ts', import.meta.url).href)};
      import { readFileSync } from 'node:fs';
      const source = readFileSync(0, 'utf8');
      const start = performance.now();
      ${parser}(source, 'adversarial.fixture');
      process.stdout.write(String(performance.now() - start));`;
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
      input: source, encoding: 'utf8', timeout: 10_000, maxBuffer: 16_384,
      env: { PATH: process.env.PATH, LANG: 'C' },
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, `${label}: ${result.stderr}`);
    const elapsed = Number(result.stdout);
    assert.ok(result.stdout && Number.isFinite(elapsed) && elapsed < 200, `${label}: ${elapsed} ms`);
    t.diagnostic(`${label}: ${elapsed.toFixed(2)} ms (< 200 ms)`);
  }
});

test('Firebase allow scanning preserves multiline grants and quoted semicolons', () => {
  const source = `service cloud.firestore {
  match /databases/{d}/documents {
    match /users/{uid} {
      allow read,
        write:
        if true;
      allow get,
        list;
      allow update: if request.auth != null
        && request.resource.data.note == "first;second";
      allow create: if request.auth != null && request.resource.data.note == 'one;two';
      allow read: if "allow write: if true;" == 'untrusted;value';
      allow read: if 'it\\'s;quoted' == "escaped\\\";value";
    }
  }
}`;
  const graph = parseFirebaseRules(source, 'multiline.firestore.rules.sample');
  const publicGrants = graph.findings.filter(item => item.ruleId.startsWith('firebase/public-'));
  assert.deepEqual(publicGrants.map(item => [item.ruleId, item.location.line]), [
    ['firebase/public-read', 4], ['firebase/public-write', 4], ['firebase/public-read', 7],
  ]);
  const fieldFindings = graph.findings.filter(item => item.ruleId === 'firebase/privilege-fields');
  assert.equal(fieldFindings.length, 2);
  assert.equal(fieldFindings[0].location.line, 9);
  assert.ok(fieldFindings[0].evidence.endsWith('"first;second";'));
  assert.ok(fieldFindings[1].evidence.endsWith("'one;two';"));
  assert.equal(graph.findings.some(item => item.ruleId.startsWith('scan/')), false);
});

test('Firebase allow conditions preserve balanced CEL maps and following clauses', () => {
  for (const expression of ['request.resource.data != {}',
    "request.resource.data == {'match': 'function service; { }', 'nested': {'service': true}}",
    'request.resource.data.service == {}', 'request.resource.data.service in {}',
    "request.resource.data.note == 'match /fake' && request.resource.data != {}",
    '["\\\n match ", {}].size() > 0',
    '(request.resource.data != {}) && request.resource.data != {}']) {
    const condition = 'request.auth != null && ' + expression;
    const source = `service cloud.firestore { match /users/{uid} { allow write: if ${condition}; allow get; } }`;
    const clauses = [...scanAllowClauses(source)];
    assert.deepEqual(clauses.map(item => item.condition), [condition, 'true']);
    assert.equal(clauses[0].evidence, `allow write: if ${condition};`);
    const graph = parseFirebaseRules(source, 'firestore.rules');
    assert.deepEqual(graph.findings.map(item => item.ruleId), ['firebase/privilege-fields', 'firebase/public-read']);
    assert.equal(graph.findings[0].evidence, clauses[0].evidence);
  }
});

test('Firebase unterminated allows reset at new block headers without swallowing nested matches', () => {
  for (const header of ['match /posts/{id}', 'match /my-posts', 'match /in', 'match /sign-in', 'match /in-box', 'match /files.in', 'function check()', 'service cloud.firestore']) {
    const source = `service cloud.firestore { match /users/{uid} {
      allow write: if request.auth != null
      ${header} { allow get: if false; }
      allow list;
    } }`;
    assert.deepEqual([...scanAllowClauses(source)].map(item => [item.operations, item.condition]),
      [[['get'], 'false'], [['list'], 'true']]);
    const graph = parseFirebaseRules(source, 'firestore.rules');
    assert.deepEqual(graph.findings.map(item => item.ruleId), ['firebase/public-read']);
    assert.equal(graph.findings[0].evidence, 'allow list;');
  }
});

test('Terraform binding lists preserve quoted delimiters and multiple members', () => {
  const graph = parseTerraform(`resource "google_project_iam_binding" "readers" {
    project = "fixture-project"
    role = "roles/secretmanager.secretAccessor"
    members = ["user:one@example.invalid", "user:two]bracket@example.invalid"]
  }`, 'main.tf');
  assert.deepEqual(graph.edges.map(edge => edge.from), [
    'identity:user:one@example.invalid', 'identity:user:two]bracket@example.invalid',
  ]);
});

test('Terraform extracts only top-level resources and stops at an unclosed tail', () => {
  const decoy = (name: string) => `resource "google_project_iam_member" "${name}" {
    project = "fixture-project" role = "roles/owner" member = "allUsers"
  }`;
  const source = `locals { ${decoy('local')} }
    terraform { ${decoy('terraform')} }
    resource "google_cloud_run_v2_service" "api" {
      nested { ${decoy('nested')} }
      ingress = "INGRESS_TRAFFIC_ALL"
    }
    ${decoy('real')}`;
  const graph = parseTerraform(source, 'main.tf');
  assert.equal(graph.findings.filter(item => item.ruleId === 'gcp/public-ingress').length, 1);
  assert.equal(graph.findings.filter(item => item.ruleId === 'gcp/public-service').length, 1);
  assert.equal(graph.edges.length, 1);
  for (const prefix of ['resource "unknown" "outer" {', 'locals {']) {
    const invalid = parseTerraform(prefix + decoy('hidden').repeat(100), 'main.tf');
    assert.deepEqual(invalid.findings.map(item => item.ruleId), ['scan/invalid-input']);
    assert.deepEqual(invalid.edges, []);
  }
});

test('HCL heredocs isolate apostrophes, comments, quotes, braces and decoy resources without shifting findings', () => {
  const directory = mkdtempSync(join(tmpdir(), 'atlas-gcp-heredoc-'));
  try {
    for (const marker of ['', '-']) for (const newline of ['\n', '\r\n']) {
      const terminator = marker ? '  EOT \t' : 'EOT \t';
      const source = `resource "google_cloud_run_v2_service" "api" {
  description = <<${marker}EOT
Team's API 日本語 # // /* " } {
${marker ? '' : '  EOT\n'}resource "google_project_iam_member" "decoy" {
  role = "roles/owner" member = "allUsers"
}
resource "google_cloud_run_v2_service" "decoy" { template { service_account = "decoy@p.iam.gserviceaccount.com" } }
${terminator}
  ingress = "INGRESS_TRAFFIC_ALL"
  notes = <<${marker}EOT
Owner's contact
${terminator}
  template { service_account = "real@p.iam.gserviceaccount.com" }
}`.replace(/\n/g, newline);
      const { text, hasHeredoc } = stripHclCommentsAndHeredocs(source);
      assert.equal(hasHeredoc, true);
      assert.equal(text.length, source.length);
      assert.deepEqual([...text.matchAll(/\r|\n/g)].map(item => item.index), [...source.matchAll(/\r|\n/g)].map(item => item.index));
      assert.equal(text.includes('decoy'), false);
      assert.equal(stripComments(source, true, false), text);
      writeFileSync(join(directory, 'main.tf'), source);
      for (const graph of [parseTerraform(source, 'main.tf'), scanDirectory(directory)]) {
        const ingress = graph.findings.filter(item => item.ruleId === 'gcp/public-ingress');
        assert.equal(ingress.length, 1);
        assert.equal(ingress[0].location.line, source.split('\n').findIndex(line => line.includes('ingress =')) + 1);
        assert.equal(graph.findings.some(item => item.ruleId === 'gcp/public-service' || item.ruleId.startsWith('scan/')), false);
        assert.equal(graph.nodes.some(item => item.id.includes('decoy')), false);
        assert.ok(graph.edges.some(item => item.from === 'tf:.:google_cloud_run_v2_service.api'
          && item.to === 'identity:real@p.iam.gserviceaccount.com'));
        assert.equal(graph.limitations.filter(item => item.includes('heredocs')).length, 1);
      }
    }
    assert.equal(stripHclCommentsAndHeredocs('x = <<EOT\n" }\nEOT').text, 'x = <<EOT\n   \n   ');
    assert.equal(stripHclCommentsAndHeredocs('# <<EOT\nx = "<<EOT"').hasHeredoc, false);
    const malformed = parseTerraform('resource "a" "b" { text = <<EOT\nnever closed\n}', 'main.tf');
    assert.deepEqual(malformed.findings.map(item => item.ruleId), ['scan/invalid-input']);
    const apostrophe = "{ ' not an HCL quote { } }";
    assert.equal(buildBraceMap(apostrophe, false).get(0), apostrophe.length - 1);
    assert.equal(closingBrace(apostrophe, 0, false), apostrophe.length - 1);
    assert.equal(closingBrace(apostrophe, 0), -1);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('WIF auth steps accept id and if before uses and connect to Secret Manager', () => {
  const account = 'worker@fixture-project.iam.gserviceaccount.com';
  const provider = 'projects/123/locations/global/workloadIdentityPools/github/providers/fixture';
  for (const header of [
    '      - uses: google-github-actions/auth@v3',
    '      - id: auth\n        uses: google-github-actions/auth@v3',
    "      - if: github.ref == 'refs/heads/main'\n        uses: google-github-actions/auth@v3",
    "      - name: Auth\n        id: auth\n        if: github.ref == 'refs/heads/main'\n        uses: 'google-github-actions/auth@v3' # trusted action",
  ]) {
    const source = `jobs:\n  inspect:\n    steps:\n${header}\n        with:\n          workload_identity_provider: ${provider}\n          service_account: '${account}'\n      - run: echo done\n`;
    const line = source.split('\n').findIndex(item => item.includes('uses:')) + 1;
    const workflow = parseWifWorkflow(source, 'workflow.yml');
    const data = parseIamPolicy(JSON.stringify({ resource: 'projects/fixture-project', bindings: [
      { role: 'roles/secretmanager.secretAccessor', members: [`serviceAccount:${account}`] },
    ] }), 'data-iam.json');
    assert.equal(workflow.edges.length, 1, header);
    assert.deepEqual(workflow.nodes.find(node => node.kind === 'entry')?.location, { file: 'workflow.yml', line });
    const graph = mergeGraphs([workflow, data]);
    const path = findAttackPaths(graph).find(path => path.nodes[0] === `entry:workflow:workflow.yml:${line}`);
    assert.ok(path, header);
    assert.equal(path.nodes[1], `identity:${account}`);
    assert.equal(path.nodes.length, 3);
    assert.match(path.description, /Secret Manager/);
    assert.equal(path.confidence, 'potential');
  }
});

test('WIF steps cannot borrow uses or inputs from nested keys, sibling steps or jobs', () => {
  const inputs = '          workload_identity_provider: projects/123/locations/global/workloadIdentityPools/github/providers/fixture\n'
    + '          service_account: worker@fixture-project.iam.gserviceaccount.com\n';
  for (const source of [
    'jobs:\n  inspect:\n    steps:\n      - name: Script\n        run: |\n          uses: google-github-actions/auth@v3\n        with:\n' + inputs,
    'jobs:\n  inspect:\n    steps:\n      - id: auth\n        uses: google-github-actions/auth@v3\n      - name: Other\n        with:\n' + inputs,
    'jobs:\n  inspect:\n    steps:\n      - uses: google-github-actions/auth@v3\n  other:\n        with:\n' + inputs,
    'jobs:\n  inspect:\n    steps:\n      - uses: google-github-actions/auth@v3\n        with:\n' + inputs.replace('projects/123', '${{ vars.PROJECT }}'),
  ]) {
    assert.deepEqual(parseWifWorkflow(source, 'workflow.yml').edges, []);
  }
});

test('WIF inputs belong only to direct with children outside YAML block scalars', () => {
  const provider = 'workload_identity_provider: projects/1/locations/global/workloadIdentityPools/p/providers/pr';
  const account = 'service_account: sa@p.iam.gserviceaccount.com';
  const header = '- uses: google-github-actions/auth@v3\n  with:\n';
  for (const scalar of ['|', '>', '|-', '|+', '>-', '>+', '|2-', '>+2']) {
    const body = `    credentials_json: ${scalar} # scalar content\n      ${provider}\n      ${account}\n`;
    assert.deepEqual(parseWifWorkflow(header + body, 'wif.yml').edges, [], scalar);
    assert.deepEqual(parseWifWorkflow(`- run: ${scalar}\n    - uses: google-github-actions/auth@v3\n      with:\n        ${provider}\n        ${account}\n`, 'wif.yml').edges, [], scalar);
    // A dedent ends the scalar; genuine peer inputs after it still work.
    const valid = parseWifWorkflow(header + body + `    ${provider}\n    ${account}\n`, 'wif.yml');
    assert.equal(valid.edges.length, 1, scalar);
    assert.equal(valid.nodes[0].location?.line, 1);
  }
  for (const body of [
    `    nested:\n      ${provider}\n      ${account}\n`,
    `    ${provider}\n    nested:\n      ${account}\n`,
    `    # comment\n\n    nested:\n      ${provider}\n      ${account}\n`,
    `    credentials_json: |\n      - uses: google-github-actions/auth@v3\n        with:\n          ${provider}\n          ${account}\n`,
  ]) assert.deepEqual(parseWifWorkflow(header + body, 'wif.yml').edges, [], body);
  const reordered = `- with:\n    # ignored\n\n    nested:\n      ${account}\n    ${provider}\n    ${account}\n  uses: google-github-actions/auth@v3\n`;
  const valid = parseWifWorkflow(reordered.replace(/\n/g, '\r\n'), 'wif.yml');
  assert.equal(valid.edges.length, 1);
  assert.equal(valid.nodes[0].location?.line, 8);
});

test('hardened enterprise has no high/blocker findings or attack paths', () => {
  const graph = scanDirectory(hardened);
  assert.deepEqual(graph.findings.filter(finding => ['high', 'blocker'].includes(finding.severity)), []);
  assert.deepEqual(graph.paths, []);
});

test('real Firestore and Storage filenames are discovered outside the repository', () => {
  const directory = mkdtempSync(join(tmpdir(), 'atlas-gcp-rules-'));
  try {
    for (const service of ['firestore', 'storage']) {
      writeFileSync(join(directory, `${service}.rules`), readFileSync(join(vulnerable, `vulnerable.${service}.rules.sample`)));
    }
    const graph = scanDirectory(directory);
    for (const service of ['firestore', 'storage']) {
      assert.ok(graph.findings.some(finding => finding.ruleId === 'firebase/public-write'
        && finding.location.file === `${service}.rules`), `Missing real ${service} rules`);
    }
    assert.ok(!graph.findings.some(finding => finding.ruleId.startsWith('scan/')));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('unconditional Firebase grants and mixed wildcard paths retain exact scopes and safe diffs', () => {
  const directory = mkdtempSync(join(tmpdir(), 'atlas-gcp-rules-'));
  const file = 'unconditional.storage.rules.sample';
  const source = `service firebase.storage {
  match /b/{bucket}/o {
    match /avatars/{file}.png { allow read, write; } // allow delete;
    match /prefix_{id} { allow get, create; }
    match /plain/{id} { allow read: if true; }
    match /private/{id} { allow read, write: if false; }
  }
}\n`;
  try {
    writeFileSync(join(directory, file), source);
    const graph = scanDirectory(directory);
    assert.equal(graph.findings.filter(item => item.ruleId === 'firebase/public-read').length, 3);
    assert.equal(graph.findings.filter(item => item.ruleId === 'firebase/public-write').length, 2);
    assert.equal(graph.findings.some(item => item.ruleId.startsWith('scan/')), false);
    for (const suffix of ['/avatars/{file}.png', '/prefix_{id}', '/plain/{id}']) {
      assert.ok(graph.nodes.some(node => node.kind === 'data' && node.label === `storage data matching /b/{bucket}/o${suffix}`));
      assert.ok(graph.paths.some(path => path.confidence === 'confirmed' && path.description.includes(suffix)));
    }
    assert.equal(graph.paths.some(path => path.description.includes('/private/')), false);
    const diffs = proposeRemediations(graph.findings, directory).filter(item => item.diff).map(item => item.diff);
    assert.equal(diffs.length, 3, 'One diff per affected line despite read and write findings');
    assert.ok(diffs.some(diff => diff.includes('+    match /avatars/{file}.png { allow read, write: if false; } // allow delete;')));
    assert.ok(diffs.some(diff => diff.includes('+    match /prefix_{id} { allow get, create: if false; }')));
    assert.ok(diffs.some(diff => diff.includes('+    match /plain/{id} { allow read: if false; }')));
    assert.equal(readFileSync(join(directory, file), 'utf8'), source);
    writeFileSync(join(directory, file), 'service firebase.storage {\n'
      + Array.from({ length: 1001 }, (_, index) => `match /path${index} { allow get; }`).join('\n') + '\n}');
    const bounded = scanDirectory(directory);
    assert.equal(bounded.paths.length, 1000);
    assert.equal(bounded.findings.filter(finding => finding.ruleId === 'scan/path-limit').length, 1);
    assert.deepEqual(bounded.findings.map(finding => finding.id), bounded.findings.map(finding => finding.id).sort());
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('WIF service-account impersonation reaches secrets and BigQuery, respecting conditions and scope', () => {
  const account = 'worker@fixture-project.iam.gserviceaccount.com';
  for (const principal of [
    'principal://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/subject/worker',
    'principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/attribute.repository/org/repo',
  ]) {
    for (const conditional of [false, true]) {
      const grants = parseIamPolicy(JSON.stringify({ resource: `projects/-/serviceAccounts/${account}`,
        bindings: [{ role: 'roles/iam.workloadIdentityUser', members: [principal],
          ...(conditional ? { condition: { expression: 'request.time < timestamp("2027-01-01T00:00:00Z")' } } : {}) }] }), 'wif-iam.json');
      const data = parseIamPolicy(JSON.stringify({ resource: 'projects/fixture-project', bindings:
        ['roles/secretmanager.secretAccessor', 'roles/bigquery.dataEditor'].map(role => ({ role, members: [`serviceAccount:${account}`] })) }), 'data-iam.json');
      const graph = mergeGraphs([grants, data]);
      const paths = findAttackPaths(graph);
      const confidence = conditional ? 'potential' : 'confirmed';
      assert.ok(grants.edges.some(edge => edge.from === `identity:${principal}` && edge.to === `identity:${account}`
        && edge.kind === 'service-account-impersonation' && edge.confidence === confidence));
      for (const destination of ['Secret Manager', 'BigQuery']) {
        assert.ok(paths.some(path => path.nodes[0] === `identity:${principal}` && path.nodes[1] === `identity:${account}`
          && path.nodes.length === 3 && path.description.includes(destination) && path.confidence === confidence));
      }
    }
  }
  for (const role of ['roles/iam.workloadIdentityPoolAdmin', 'iam.serviceAccounts.implicitDelegation']) {
    const graph = parseIamPolicy(JSON.stringify({ resource: `projects/-/serviceAccounts/${account}`,
      bindings: [{ role, members: ['user:fixture@example.invalid'] }] }), 'escalation-iam.json');
    assert.ok(graph.findings.some(finding => finding.ruleId === 'iam/privilege-escalation'));
    assert.equal(graph.edges[0].confidence, role.endsWith('Admin') ? 'potential' : 'confirmed');
  }
  const unresolved = parseIamPolicy(JSON.stringify({ bindings: [{ role: 'roles/iam.workloadIdentityUser',
    members: ['principalSet://fixture/pool/*'] }] }), 'unresolved-iam.json');
  assert.equal(unresolved.edges.some(edge => edge.kind === 'service-account-impersonation'), false);
});

test('Terraform email, id and name references correlate runtime identities across files', () => {
  const directory = mkdtempSync(join(tmpdir(), 'atlas-gcp-terraform-'));
  try {
    writeFileSync(join(directory, 'identity.tf'), `resource "google_service_account" "worker" {
      account_id = "worker"
      project = "fixture-project"
    }
    resource "google_project_iam_member" "secrets" {
      project = "fixture-project"
      role = "roles/secretmanager.secretAccessor"
      member = "serviceAccount:worker@fixture-project.iam.gserviceaccount.com"
    }`);
    for (const attribute of ['email', 'id', 'name']) {
      for (const interpolated of [false, true]) {
        const reference = `google_service_account.worker.${attribute}`;
        const expression = interpolated ? JSON.stringify('${' + reference + '}') : reference;
        writeFileSync(join(directory, 'runtime.tf'), `resource "google_cloud_run_v2_service" "api" {
          name = "api"
          template { service_account = ${expression} }
        }
        resource "google_cloud_run_v2_service_iam_member" "public" {
          service = google_cloud_run_v2_service.api.name
          role = "roles/run.invoker"
          member = "allUsers"
        }`);
        const graph = scanDirectory(directory);
        assert.ok(graph.paths.some(path => path.nodes[0] === 'entry:iam:allUsers'
          && path.nodes.includes('identity:worker@fixture-project.iam.gserviceaccount.com')
          && path.description.includes('Secret Manager') && path.confidence === 'potential'), expression);
        assert.equal(graph.limitations.some(item => item.includes('Runtime identity could not be resolved')), false, expression);
      }
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('GKE node identity exposure, Cloud SQL 0.0.0.0/0 paths and Cloud Build default SA grants are detected and remediated', () => {
  const directory = mkdtempSync(join(tmpdir(), 'atlas-gcp-gke-sql-'));
  const source = [
    'resource "google_container_cluster" "primary" {',
    '  name = "primary"',
    '  node_config {',
    '    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]',
    '  }',
    '}',
    'resource "google_sql_database_instance" "main_db" {',
    '  name = "main-db"',
    '  settings {',
    '    ip_configuration {',
    '      ipv4_enabled = true',
    '      authorized_networks {',
    '        value = "0.0.0.0/0"',
    '      }',
    '    }',
    '  }',
    '}',
    'resource "google_project_iam_member" "cb_admin" {',
    '  project = "fixture-project"',
    '  role = "roles/cloudsql.admin"',
    '  member = "serviceAccount:123456789@cloudbuild.gserviceaccount.com"',
    '}',
  ].join('\n') + '\n';
  try {
    writeFileSync(join(directory, 'main.tf'), source);
    const graph = scanDirectory(directory);
    const ruleIds = new Set(graph.findings.map(finding => finding.ruleId));
    assert.ok(ruleIds.has('gke/node-identity-exposure'));
    assert.ok(ruleIds.has('sql/public-authorized-network'));
    assert.ok(ruleIds.has('sql/unencrypted-public-ip'));
    assert.ok(ruleIds.has('iam/default-service-account'));
    assert.ok(graph.paths.some(path => path.nodes[0] === 'entry:sql:0.0.0.0/0'
      && path.description.includes('Cloud SQL database in google_sql_database_instance.main_db')
      && path.confidence === 'confirmed' && path.severity === 'blocker'));
    const proposals = proposeRemediations(graph.findings, directory);
    const sqlDiff = proposals.find(item => item.diff.includes('127.0.0.1/32'));
    assert.ok(sqlDiff, 'Expected review-only diff for 0.0.0.0/0 authorized_networks');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
