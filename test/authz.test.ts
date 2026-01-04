// Copyright 2026 The Casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { newEnforcer, Enforcer } from 'casbin';
import { authz, Authorizer } from '../src/authz';
import type { RequestEventCommon } from '@builder.io/qwik-city';
import path from 'path';

// Mock RequestEventCommon for testing
function createMockEvent(
  url: string,
  method: string,
  authHeader?: string,
  customUsername?: string
): RequestEventCommon {
  const headers = new Map<string, string>();
  if (authHeader) {
    headers.set('authorization', authHeader);
  }

  const sharedMap = new Map<string, any>();
  if (customUsername) {
    sharedMap.set('username', customUsername);
  }

  return {
    request: {
      method,
      headers: {
        get: (name: string) => headers.get(name.toLowerCase()) || null,
      },
    } as any,
    url: new URL(url, 'http://localhost'),
    sharedMap,
  } as RequestEventCommon;
}

describe('Qwik Authz Middleware', () => {
  let enforcer: Enforcer;

  beforeAll(async () => {
    const modelPath = path.join(__dirname, 'fixtures/model.conf');
    const policyPath = path.join(__dirname, 'fixtures/policy.csv');
    enforcer = await newEnforcer(modelPath, policyPath);
  });

  describe('Basic Authentication - Allowed requests', () => {
    test('alice can GET /dataset1/resource', async () => {
      const event = createMockEvent(
        'http://localhost/dataset1/resource',
        'GET',
        `Basic ${Buffer.from('alice:password').toString('base64')}`
      );

      const middleware = authz({ newEnforcer: enforcer });
      const result = await middleware(event);

      expect(result).toBeUndefined();
    });

    test('alice can POST /dataset1/resource1', async () => {
      const event = createMockEvent(
        'http://localhost/dataset1/resource1',
        'POST',
        `Basic ${Buffer.from('alice:password').toString('base64')}`
      );

      const middleware = authz({ newEnforcer: enforcer });
      const result = await middleware(event);

      expect(result).toBeUndefined();
    });

    test('bob can POST /dataset2/folder1/file', async () => {
      const event = createMockEvent(
        'http://localhost/dataset2/folder1/file',
        'POST',
        `Basic ${Buffer.from('bob:password').toString('base64')}`
      );

      const middleware = authz({ newEnforcer: enforcer });
      const result = await middleware(event);

      expect(result).toBeUndefined();
    });

    test('bob can GET /dataset2/resource1', async () => {
      const event = createMockEvent(
        'http://localhost/dataset2/resource1',
        'GET',
        `Basic ${Buffer.from('bob:password').toString('base64')}`
      );

      const middleware = authz({ newEnforcer: enforcer });
      const result = await middleware(event);

      expect(result).toBeUndefined();
    });

    test('bob can POST /dataset2/resource1', async () => {
      const event = createMockEvent(
        'http://localhost/dataset2/resource1',
        'POST',
        `Basic ${Buffer.from('bob:password').toString('base64')}`
      );

      const middleware = authz({ newEnforcer: enforcer });
      const result = await middleware(event);

      expect(result).toBeUndefined();
    });

    test('cathy (dataset1_admin) can GET /dataset1/resource', async () => {
      const event = createMockEvent(
        'http://localhost/dataset1/resource',
        'GET',
        `Basic ${Buffer.from('cathy:password').toString('base64')}`
      );

      const middleware = authz({ newEnforcer: enforcer });
      const result = await middleware(event);

      expect(result).toBeUndefined();
    });

    test('cathy (dataset1_admin) can DELETE /dataset1/resource', async () => {
      const event = createMockEvent(
        'http://localhost/dataset1/resource',
        'DELETE',
        `Basic ${Buffer.from('cathy:password').toString('base64')}`
      );

      const middleware = authz({ newEnforcer: enforcer });
      const result = await middleware(event);

      expect(result).toBeUndefined();
    });
  });

  describe('Basic Authentication - Forbidden requests', () => {
    test('alice cannot POST /dataset1/resource', async () => {
      const event = createMockEvent(
        'http://localhost/dataset1/resource',
        'POST',
        `Basic ${Buffer.from('alice:password').toString('base64')}`
      );

      const middleware = authz({ newEnforcer: enforcer });
      const result = await middleware(event);

      expect(result).toBeInstanceOf(Response);
      expect(result?.status).toBe(403);
      const body = await result?.json();
      expect(body).toEqual({ error: 'Forbidden' });
    });

    test('bob cannot GET /dataset2/folder1/file', async () => {
      const event = createMockEvent(
        'http://localhost/dataset2/folder1/file',
        'GET',
        `Basic ${Buffer.from('bob:password').toString('base64')}`
      );

      const middleware = authz({ newEnforcer: enforcer });
      const result = await middleware(event);

      expect(result).toBeInstanceOf(Response);
      expect(result?.status).toBe(403);
    });

    test('unauthorized user cannot access protected resource', async () => {
      const event = createMockEvent(
        'http://localhost/dataset1/resource',
        'GET',
        `Basic ${Buffer.from('charlie:password').toString('base64')}`
      );

      const middleware = authz({ newEnforcer: enforcer });
      const result = await middleware(event);

      expect(result).toBeInstanceOf(Response);
      expect(result?.status).toBe(403);
    });

    test('request without auth header is forbidden', async () => {
      const event = createMockEvent('http://localhost/dataset1/resource', 'GET');

      const middleware = authz({ newEnforcer: enforcer });
      const result = await middleware(event);

      expect(result).toBeInstanceOf(Response);
      expect(result?.status).toBe(403);
    });
  });

  describe('Custom username via sharedMap', () => {
    test('alice can GET /dataset1/resource with custom username', async () => {
      const event = createMockEvent(
        'http://localhost/dataset1/resource',
        'GET',
        undefined,
        'alice'
      );

      const middleware = authz({ newEnforcer: enforcer });
      const result = await middleware(event);

      expect(result).toBeUndefined();
    });

    test('bob cannot GET /dataset1/resource with custom username', async () => {
      const event = createMockEvent(
        'http://localhost/dataset1/resource',
        'GET',
        undefined,
        'bob'
      );

      const middleware = authz({ newEnforcer: enforcer });
      const result = await middleware(event);

      expect(result).toBeInstanceOf(Response);
      expect(result?.status).toBe(403);
    });
  });

  describe('Custom Authorizer', () => {
    class CustomAuthorizer implements Authorizer {
      private event: RequestEventCommon;
      private enforcer: Enforcer;

      constructor(event: RequestEventCommon, enforcer: Enforcer) {
        this.event = event;
        this.enforcer = enforcer;
      }

      async checkPermission(): Promise<boolean> {
        // Custom logic: always allow GET requests to /public/*
        if (
          this.event.request.method === 'GET' &&
          this.event.url.pathname.startsWith('/public/')
        ) {
          return true;
        }

        // For other requests, use default casbin enforcement
        const username = this.event.sharedMap.get('username') as string;
        return this.enforcer.enforce(
          username,
          this.event.url.pathname,
          this.event.request.method
        );
      }
    }

    test('custom authorizer allows GET /public/resource', async () => {
      const event = createMockEvent('http://localhost/public/resource', 'GET');

      const middleware = authz({
        newEnforcer: enforcer,
        authorizer: CustomAuthorizer,
      });
      const result = await middleware(event);

      expect(result).toBeUndefined();
    });

    test('custom authorizer still enforces policy for non-public paths', async () => {
      const event = createMockEvent(
        'http://localhost/dataset1/resource',
        'GET',
        undefined,
        'alice'
      );

      const middleware = authz({
        newEnforcer: enforcer,
        authorizer: CustomAuthorizer,
      });
      const result = await middleware(event);

      expect(result).toBeUndefined();
    });
  });

  describe('Promise-based enforcer', () => {
    test('works with enforcer wrapped in Promise', async () => {
      const enforcerPromise = Promise.resolve(enforcer);

      const event = createMockEvent(
        'http://localhost/dataset1/resource',
        'GET',
        `Basic ${Buffer.from('alice:password').toString('base64')}`
      );

      const middleware = authz({ newEnforcer: enforcerPromise });
      const result = await middleware(event);

      expect(result).toBeUndefined();
    });
  });

  describe('Error handling', () => {
    test('throws error with invalid enforcer', async () => {
      const event = createMockEvent('http://localhost/test', 'GET');

      const middleware = authz({ newEnforcer: {} as any });

      await expect(middleware(event)).rejects.toThrow('Invalid enforcer');
    });
  });
});
