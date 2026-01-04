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

import { newEnforcer } from 'casbin';
import { authz } from 'qwik-authz';
import type { RequestHandler } from '@builder.io/qwik-city';

/**
 * Example: Custom authentication (e.g., JWT, OAuth)
 */

const enforcer = await newEnforcer('examples/model.conf', 'examples/policy.csv');

/**
 * Custom middleware to extract username from JWT or other auth method
 */
export const onRequest: RequestHandler = async (event) => {
  // Your custom logic to extract username
  // For example, from JWT token, session, etc.
  const token = event.request.headers.get('Authorization')?.replace('Bearer ', '');
  
  if (token) {
    // Decode your token and extract username
    const username = decodeToken(token); // Your token decoding logic
    
    // Set username in sharedMap for authz middleware to use
    event.sharedMap.set('username', username);
  }
  
  // Continue to next middleware
};

/**
 * Apply authz middleware after authentication
 */
export const onGet: RequestHandler = authz({ newEnforcer: enforcer });

/**
 * Placeholder function - implement your own token decoding
 */
function decodeToken(token: string): string {
  // Implement your JWT decoding logic here
  return 'username-from-token';
}
