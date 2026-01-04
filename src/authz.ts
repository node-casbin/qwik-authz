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

import { Enforcer } from 'casbin';
import type { RequestEventCommon } from '@builder.io/qwik-city';

/**
 * Interface for custom authorizer implementations
 */
export interface Authorizer {
  /**
   * Check if the current request is authorized
   */
  checkPermission(): Promise<boolean>;
}

/**
 * Constructor interface for custom authorizer classes
 */
interface AuthorizerConstructor {
  new (event: RequestEventCommon, enforcer: Enforcer): Authorizer;
}

/**
 * BasicAuthorizer provides basic authorization using HTTP Basic Authentication
 */
class BasicAuthorizer implements Authorizer {
  private event: RequestEventCommon;
  private enforcer: Enforcer;

  constructor(event: RequestEventCommon, enforcer: Enforcer) {
    this.event = event;
    this.enforcer = enforcer;
  }

  /**
   * Extract username from the request
   * Supports HTTP Basic Authentication and custom username in sharedMap
   */
  private getUserName(): string {
    // First check if username is set in sharedMap (for custom auth)
    const username = this.event.sharedMap.get('username');
    if (username) {
      return username as string;
    }

    // Fall back to HTTP Basic Authentication
    try {
      const authHeader = this.event.request.headers.get('Authorization');
      if (!authHeader) return '';

      const parts = authHeader.split(' ');
      if (parts.length !== 2 || parts[0].trim() !== 'Basic') return '';

      const credentials = Buffer.from(parts[1], 'base64').toString('ascii');
      const [user] = credentials.split(':');
      return user || '';
    } catch (e) {
      console.error('Error parsing authorization header:', e);
      return '';
    }
  }

  /**
   * Check if the user has permission to access the resource
   */
  async checkPermission(): Promise<boolean> {
    const user = this.getUserName();
    const path = this.event.url.pathname;
    const method = this.event.request.method;

    return this.enforcer.enforce(user, path, method);
  }
}

/**
 * Options for configuring the authz middleware
 */
export interface AuthzOptions {
  /**
   * The Casbin enforcer instance (can be a Promise)
   */
  newEnforcer: Enforcer | Promise<Enforcer>;
  /**
   * Optional custom authorizer (instance or constructor)
   */
  authorizer?: Authorizer | AuthorizerConstructor;
}

/**
 * Create authorization middleware for Qwik
 * 
 * @param options Configuration options
 * @returns Qwik middleware function
 * 
 * @example
 * ```typescript
 * import { authz } from 'qwik-authz';
 * import { newEnforcer } from 'casbin';
 * 
 * const enforcer = await newEnforcer('model.conf', 'policy.csv');
 * 
 * export const onRequest = authz({ newEnforcer: enforcer });
 * ```
 */
export function authz(options: AuthzOptions) {
  return async (event: RequestEventCommon) => {
    const enforcer = await Promise.resolve(options.newEnforcer);

    if (!(enforcer instanceof Enforcer)) {
      throw new Error('Invalid enforcer: expected Casbin Enforcer instance');
    }

    // Create or use provided authorizer
    const authorizer = options.authorizer
      ? typeof options.authorizer === 'function'
        ? new options.authorizer(event, enforcer)
        : options.authorizer
      : new BasicAuthorizer(event, enforcer);

    // Check permission
    const isAllowed = await authorizer.checkPermission();

    if (!isAllowed) {
      // Return 403 Forbidden response
      return new Response(JSON.stringify({ error: 'Forbidden' }), {
        status: 403,
        headers: {
          'Content-Type': 'application/json',
        },
      });
    }

    // If authorized, continue to next middleware/handler
    // (return nothing to continue the middleware chain)
  };
}
