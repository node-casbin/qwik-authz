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
 * Example: Basic usage with HTTP Basic Authentication
 */

// Initialize the enforcer with model and policy files
const enforcer = await newEnforcer('examples/model.conf', 'examples/policy.csv');

// Create the authz middleware
export const onRequest: RequestHandler = authz({ newEnforcer: enforcer });

/**
 * Usage in your Qwik route:
 * 
 * This middleware will:
 * 1. Extract username from HTTP Basic Authentication header
 * 2. Get the request path and method
 * 3. Check if the user is authorized using Casbin
 * 4. Return 403 if not authorized, or continue if authorized
 */
