// This file is part of vibe-check — the open-source, local deep-scan engine from peek.software (https://peek.software) that audits AI-generated SaaS apps.
// SPDX-License-Identifier: Apache-2.0

// @ts-check
/**
 * @fileoverview Unit tests for the Checkov (IaC) provider.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { checkovProvider, findIaCFiles, isIaCFile, parseCheckovJson, buildScanArgs } from '../src/providers/checkov.mjs';

test('isIaCFile recognizes IaC by name', () => {
  assert.equal(isIaCFile('infra/main.tf'), true);
  assert.equal(isIaCFile('infra/main.tf.json'), true);
  assert.equal(isIaCFile('Dockerfile'), true);
  assert.equal(isIaCFile('docker/Dockerfile.prod'), true);
  assert.equal(isIaCFile('docker-compose.yml'), true);
  assert.equal(isIaCFile('compose.yaml'), true);
  assert.equal(isIaCFile('serverless.yml'), true);
  assert.equal(isIaCFile('stack.template'), true);
  assert.equal(isIaCFile('main.bicep'), true);
  assert.equal(isIaCFile('src/app.js'), false);
  assert.equal(isIaCFile('composer.json'), false);
});

test('isIaCFile recognizes IaC by content (CloudFormation + k8s)', () => {
  assert.equal(isIaCFile('stack.yaml', 'AWSTemplateFormatVersion: "2010-09-09"\nResources: {}\n'), true);
  assert.equal(
    isIaCFile('deploy.yaml', 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n'),
    true,
  );
  assert.equal(isIaCFile('config.yaml', 'database:\n  host: localhost\n'), false);
  // Content markers require content — a yaml file with no content read is not IaC.
  assert.equal(isIaCFile('stack.yaml', null), false);
});

test('findIaCFiles collects IaC files under targets + root, skips others', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibe-checkov-'));
  try {
    mkdirSync(join(root, 'infra'), { recursive: true });
    writeFileSync(join(root, 'infra', 'main.tf'), 'resource "aws_s3_bucket" "b" {}\n');
    writeFileSync(join(root, 'infra', 'deploy.yaml'), 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n');
    writeFileSync(join(root, 'infra', 'notes.yaml'), 'team: platform\n');
    writeFileSync(join(root, 'Dockerfile'), 'FROM node:22\n');
    writeFileSync(join(root, 'app.js'), 'export const x = 1;\n');

    const found = findIaCFiles(root, [join(root, 'infra')]).sort();
    assert.deepEqual(found, ['Dockerfile', 'infra/deploy.yaml', 'infra/main.tf']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('parseCheckovJson maps severities, pillars, and advisory flag', () => {
  const stdout = JSON.stringify({
    results: {
      failed_checks: [
        {
          check_id: 'CKV_AWS_111',
          check_name: 'Ensure IAM policies does not allow full Resource wildcard',
          file_abs_path: '/repo/infra/iam.tf',
          file_path: '/repo/infra/iam.tf',
          file_line_range: [4, 9],
          resource: 'aws_iam_policy.wild',
          severity: 'HIGH',
          guideline: 'https://docs.bridgecrew.io/docs/ensure-iam-policies-do-not-allow-full-resource-wildcard',
        },
        {
          check_id: 'CKV_DOCKER_3',
          check_name: 'Ensure that a user for the container has been created',
          file_abs_path: '/repo/Dockerfile',
          file_path: '/repo/Dockerfile',
          file_line_range: [1, 1],
          resource: 'Dockerfile.',
          severity: 'MEDIUM',
          guideline: null,
        },
      ],
    },
  });

  const findings = parseCheckovJson(stdout, '/repo');
  assert.equal(findings.length, 2);

  const iam = findings.find((f) => f.source.ruleId === 'CKV_AWS_111');
  assert.ok(iam);
  assert.equal(iam.severity, 'high');
  assert.equal(iam.pillar, 'security');
  assert.equal(iam.advisory, false); // high → scored
  assert.equal(iam.file, 'infra/iam.tf');
  assert.equal(iam.line, 4);
  assert.match(iam.title, /IAM policies/);
  assert.ok(iam.fixSummary, 'guideline becomes the fix hint');

  const docker = findings.find((f) => f.source.ruleId === 'CKV_DOCKER_3');
  assert.ok(docker);
  assert.equal(docker.severity, 'medium');
  assert.equal(docker.pillar, 'runtime');
  assert.equal(docker.advisory, true); // medium → advisory
});

test('buildScanArgs targets IaC files (--file) and Terraform dirs (--directory)', () => {
  const args = buildScanArgs('/repo', ['docker-compose.yml', 'docker/fpm/Dockerfile', 'infra/main.tf', 'infra/modules/x.tf']);
  // Files → --file (absolute); .tf → their parent directory (deduped).
  assert.ok(args.includes('--file'));
  assert.ok(args.includes('--skip-framework') && args.includes('secrets'), 'secrets framework is skipped');
  const fileArgs = args.filter((a) => a.startsWith('/repo/'));
  assert.deepEqual(fileArgs, ['/repo/docker-compose.yml', '/repo/docker/fpm/Dockerfile', '/repo/infra']);
  assert.ok(!args.some((a) => a.includes('modules')), 'only parent dirs are passed, not each tf file');
});

test('parseCheckovJson handles the array shape + null severity (checkov 3.x)', () => {
  const stdout = JSON.stringify([
    {
      check_type: 'dockerfile',
      results: {
        failed_checks: [
          {
            check_id: 'CKV_DOCKER_2',
            check_name: 'Ensure that containers do not run with root user',
            file_abs_path: '/repo/backend/Dockerfile',
            file_line_range: [1, 15],
            resource: 'backend/Dockerfile.',
            severity: null,
          },
        ],
      },
    },
    {
      check_type: 'terraform',
      results: {
        failed_checks: [
          {
            check_id: 'CKV_AWS_111',
            check_name: 'Ensure IAM policies does not allow full Resource wildcard',
            file_abs_path: '/repo/infra/iam.tf',
            file_line_range: [4, 9],
            resource: 'aws_iam_policy.wild',
            severity: null,
          },
        ],
      },
    },
  ]);

  const findings = parseCheckovJson(stdout, '/repo');
  assert.equal(findings.length, 2);

  const docker = findings.find((f) => f.source.ruleId === 'CKV_DOCKER_2');
  assert.ok(docker);
  assert.equal(docker.severity, 'medium'); // null → default medium
  assert.equal(docker.pillar, 'runtime');
  assert.equal(docker.advisory, true);

  const iam = findings.find((f) => f.source.ruleId === 'CKV_AWS_111');
  assert.ok(iam);
  assert.equal(iam.severity, 'high'); // IAM wildcard → high even when null
  assert.equal(iam.pillar, 'security');
  assert.equal(iam.advisory, false);
});

test('checkov provider skips gracefully when the repo has no IaC', async () => {
  const root = mkdtempSync(join(tmpdir(), 'vibe-checkov-'));
  try {
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, 'src', 'app.js'), 'export const x = 1;\n');
    const findings = await checkovProvider.run(
      /** @type {any} */ ({}),
      /** @type {any} */ ({ repoRoot: root, targets: [join(root, 'src')], log: () => {} }),
    );
    assert.deepEqual(findings, []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
