# Qwik-Authz

[![CI](https://github.com/node-casbin/qwik-authz/actions/workflows/ci.yml/badge.svg)](https://github.com/node-casbin/qwik-authz/actions/workflows/ci.yml)
[![NPM version](https://img.shields.io/npm/v/qwik-authz.svg?style=flat-square)](https://npmjs.com/package/qwik-authz)
[![NPM download](https://img.shields.io/npm/dm/qwik-authz.svg?style=flat-square)](https://npmjs.com/package/qwik-authz)
[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/S5UjpzGZjN)

Qwik-Authz is an authorization middleware for [Qwik](https://qwik.builder.io/), based on [Node-Casbin](https://github.com/casbin/node-casbin).

## Installation

```bash
npm install qwik-authz casbin
```

## Quick Start

### Basic Usage with HTTP Basic Authentication

```typescript
// src/routes/layout.tsx or plugin.ts
import { newEnforcer } from 'casbin';
import { authz } from 'qwik-authz';
import type { RequestHandler } from '@builder.io/qwik-city';

// Initialize Casbin enforcer
const enforcer = await newEnforcer('path/to/model.conf', 'path/to/policy.csv');

// Apply authz middleware
export const onRequest: RequestHandler = authz({ newEnforcer: enforcer });
```

By default, qwik-authz uses HTTP Basic Authentication in the format:
```
Authorization: Basic {Base64Encoded(username:password)}
```

### Usage with Custom Authentication (JWT, OAuth, etc.)

For other authentication methods, set the username in `event.sharedMap` before applying the authz middleware:

```typescript
import { newEnforcer } from 'casbin';
import { authz } from 'qwik-authz';
import type { RequestHandler } from '@builder.io/qwik-city';

const enforcer = await newEnforcer('path/to/model.conf', 'path/to/policy.csv');

// Custom authentication middleware
export const onRequest: RequestHandler = async (event) => {
  // Extract username from your auth method (JWT, session, etc.)
  const token = event.request.headers.get('Authorization')?.replace('Bearer ', '');
  
  if (token) {
    const username = await verifyToken(token); // Your token verification logic
    event.sharedMap.set('username', username);
  }
};

// Apply authz middleware
export const onGet: RequestHandler = authz({ newEnforcer: enforcer });
```

### Usage with Custom Authorizer

Implement the `Authorizer` interface to add custom authorization logic:

```typescript
import { Enforcer, newEnforcer } from 'casbin';
import { authz, Authorizer } from 'qwik-authz';
import type { RequestHandler, RequestEventCommon } from '@builder.io/qwik-city';

const enforcer = await newEnforcer('path/to/model.conf', 'path/to/policy.csv');

class CustomAuthorizer implements Authorizer {
  private event: RequestEventCommon;
  private enforcer: Enforcer;

  constructor(event: RequestEventCommon, enforcer: Enforcer) {
    this.event = event;
    this.enforcer = enforcer;
  }

  async checkPermission(): Promise<boolean> {
    // Allow public access to certain paths
    if (this.event.url.pathname.startsWith('/public/')) {
      return true;
    }

    // Use Casbin for other paths
    const username = this.event.sharedMap.get('username') as string || 'anonymous';
    return this.enforcer.enforce(
      username,
      this.event.url.pathname,
      this.event.request.method
    );
  }
}

export const onRequest: RequestHandler = authz({
  newEnforcer: enforcer,
  authorizer: CustomAuthorizer,
});
```

## How Authorization Works

The authorization is determined based on `{subject, object, action}`:

- **subject**: The logged-in username
- **object**: The URL path (e.g., `/dataset1/resource`)
- **action**: The HTTP method (GET, POST, PUT, DELETE, etc.)

### Example Model File (`model.conf`)

```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && keyMatch(r.obj, p.obj) && (r.act == p.act || p.act == "*")
```

### Example Policy File (`policy.csv`)

```csv
p, alice, /dataset1/*, GET
p, alice, /dataset1/resource1, POST
p, bob, /dataset2/*, *
p, admin, /*, *

g, alice, admin
```

In this example:
- `alice` can `GET` any resource under `/dataset1/` and `POST` to `/dataset1/resource1`
- `bob` can perform any action on resources under `/dataset2/`
- `admin` role has access to all resources
- `alice` has the `admin` role (via role inheritance)

## API Reference

### `authz(options: AuthzOptions)`

Creates an authorization middleware for Qwik.

#### Parameters

- `options.newEnforcer` - A Casbin `Enforcer` instance or Promise that resolves to one
- `options.authorizer` - (Optional) Custom `Authorizer` instance or constructor

#### Returns

A Qwik `RequestHandler` middleware function

### `Authorizer` Interface

```typescript
interface Authorizer {
  checkPermission(): Promise<boolean>;
}
```

Implement this interface to create custom authorization logic.

## Examples

See the [examples](./examples) directory for more usage examples:

- [basic.ts](./examples/basic.ts) - Basic usage with HTTP Basic Authentication
- [custom-auth.ts](./examples/custom-auth.ts) - Custom authentication methods
- [custom-authorizer.ts](./examples/custom-authorizer.ts) - Custom authorization logic

## Documentation

For more information about Casbin and policy configuration:

- [Casbin Documentation](https://casbin.org)
- [Node-Casbin](https://github.com/casbin/node-casbin)
- [Qwik Documentation](https://qwik.builder.io/)

## License

This project is licensed under the [Apache 2.0 License](LICENSE).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

- [GitHub Issues](https://github.com/node-casbin/qwik-authz/issues)
- [Discord Community](https://discord.gg/S5UjpzGZjN)