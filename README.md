# Auth

`Auth` is a Rails engine for attaching token-based authentication, Doorkeeper integration, identity records, and two-factor authentication providers to application models.

It gives you:

- an `authenticatable` decorator that turns an application model into a token-capable resource owner
- first-party Doorkeeper-backed models for applications, access grants, and access tokens
- identity and two-factor authentication persistence models
- route helpers and controller wiring for token issuance, refresh, revoke, and introspection flows
- extension points for Doorkeeper behavior, OmniAuth identity linking, two-factor providers, and Grape authorization helpers

`auth` is designed to be expanded from the application. The engine supplies the auth models and the decorator DSL; the application decides which models are authenticatable, how credentials are resolved, which grant types are enabled, whether two-factor authentication is required, and which token routes are exposed.

## What Problem This Solves

Use this engine when your app needs both of these at the same time:

- one or more application models that can authenticate and issue OAuth-style access tokens
- a reusable extension layer for identity providers, token behavior, and two-factor verification

Why this matters:

- an authenticatable model answers "which application record can log in and own tokens?"
- Doorkeeper answers "how are access grants and access tokens issued and verified?"
- an identity answers "which external provider account is linked to this record?"
- a two-factor provider answers "how is secondary verification initiated and confirmed?"

If you only wire Devise or Doorkeeper directly on one model, the token flow stays coupled to a single application layout. `Auth` restores a consistent abstraction so multiple authenticatable models can share the same token infrastructure while still overriding credentials, scopes, token response shape, provider logic, and route exposure.

## How The Engine Works

The engine revolves around five concepts:

- `authenticatable`
- `application`
- `access token`
- `identity`
- `two-factor provider`

At the base level:

- `authenticatable` decorates an application model with auth configuration, associations, and helper methods
- `Auth::Application` stores OAuth client applications
- `Auth::AccessGrant` and `Auth::AccessToken` store Doorkeeper grants and tokens
- `Auth::Identity` stores external-identity mappings for OmniAuth-style logins
- `Auth::TwoFactorAuthenticationProvider` and `Auth::TwoFactorAuthenticationSession` store provider configuration and verification sessions

Example:

```ruby
class User < ApplicationRecord
  authenticatable do
    doorkeeper do
      enabled true
    end
  end
end
```

That is the low-level interface:

- the application still owns the `User` model
- the engine adds auth associations and config through `authenticatable`
- Doorkeeper remains the token engine underneath
- the route layer uses the authenticatable config to decide how token requests should be handled

When a class is marked `authenticatable`, the engine registers it in `Auth::Models::Decorators::Authenticatable.registered_classes`. Route helpers later use that registry to expose token endpoints only for classes with `doorkeeper.enabled`.

## Extending Authenticatable And Token Behavior

The extension surface is not only "decorate a model". Applications can keep engine defaults, or they can override the parts that control provider resolution, token issuance, identity linkage, or second-factor behavior.

Think about the application API in two layers:

- defaults: what the engine infers from the authenticatable class, Doorkeeper config, provider names, and built-in callbacks
- overrides: what you redefine when you want authentication behavior to read like your domain instead of the raw engine defaults

For authenticatable models, the main extension hooks are:

- `authenticatable "name"`
- `native_provider`
- `doorkeeper.enabled`
- `doorkeeper.grant_types`
- `doorkeeper.default_grant_type`
- `doorkeeper.allowed_scopes`
- `doorkeeper.default_scope`
- `doorkeeper.default_application`
- `doorkeeper.custom_token_response`
- `doorkeeper.resource_owner_authenticator`
- `doorkeeper.resource_owner_from_credentials`
- `doorkeeper.jwt_payload`
- `doorkeeper.access_token_expires_in`
- `two_factor_authentication.enabled`
- `two_factor_authentication.providers`
- `omni_authentication.enabled`
- `omni_authentication.providers`
- `omni_authentication.auth_hash_mapping`
- `omni_authentication.authenticatable_finder`
- `omni_authentication.identity_finder`

Example:

```ruby
class AdminUser < ApplicationRecord
  authenticatable "admin" do
    doorkeeper do
      enabled true
      grant_types ["password", "refresh_token"]
      default_scope "admin"

      resource_owner_from_credentials do |request|
        admin = find_by(email: request.params[:email])
        if admin&.valid_password?(request.params[:password])
          admin
        end
      end

      custom_token_response do |payload|
        payload.merge("audience" => "admin-panel")
      end
    end
  end
end
```

With overrides like these, the application can shape:

- which models issue tokens
- which grant types each authenticatable model accepts
- which scopes a model exposes by default
- how resource owners are resolved from credentials
- how token responses are reshaped before being returned
- whether two-factor and OmniAuth flows are enabled for a given authenticatable class

## Installation

Add the engine to the application:

```ruby
gem "auth", path: "engines/authentication"
```

Install the auth tables, generate the auth initializer, and migrate:

```bash
bundle install
bin/rails auth:install
bin/rails generate auth:config
bin/rails db:migrate
```

The install generator also supports UUID primary-key setups:

```bash
bin/rails auth:install --uuid
```

If the application uses token routes, expose them in `config/routes.rb`:

```ruby
Rails.application.routes.draw do
  use_doorkeeper_token_authenticatable_routes
end
```

## What The Engine Ships

Persistent model classes:

- `Auth::Application`
- `Auth::AccessGrant`
- `Auth::AccessToken`
- `Auth::Identity`
- `Auth::TwoFactorAuthenticationProvider`
- `Auth::TwoFactorAuthenticationSession`

Decorator namespaces:

- `Auth::Models::Decorators::Authenticatable`
- `Auth::Models::Decorators::TwoFactorAuthenticationProvider::Object`
- `Auth::Models::Decorators::TwoFactorAuthenticationSession::Object`

Controller and route helpers:

- `Auth::Doorkeeper::SessionsController`
- `Auth::Controllers::Concerns::DoorkeeperTokens`
- `Auth::Routes.use_doorkeeper_token_authenticatable_routes`
- `Auth::Routes.use_doorkeeper_token_authenticatable_route`

Doorkeeper integration surfaces:

- `Auth::Configuration::Doorkeeper`
- `Auth::Doorkeeper::Strategies::OTP`
- `Auth::Doorkeeper::Decorators::HttpOnlyTokenResponse`

Grape integration surfaces:

- `Auth::Grape::Helpers::Doorkeeper`

Two-factor provider layer:

- `Auth::Providers::TwoFactorAuthentication`
- `Auth::Providers::TwoFactorAuthentication::Totp`

## Core Model Design

The base models are intentionally thin:

- [app/models/auth/application.rb](/home/ihsan/Works/VirtualSpirit/Ruby/engines/authentication/app/models/auth/application.rb)
- [app/models/auth/access_grant.rb](/home/ihsan/Works/VirtualSpirit/Ruby/engines/authentication/app/models/auth/access_grant.rb)
- [app/models/auth/access_token.rb](/home/ihsan/Works/VirtualSpirit/Ruby/engines/authentication/app/models/auth/access_token.rb)
- [app/models/auth/identity.rb](/home/ihsan/Works/VirtualSpirit/Ruby/engines/authentication/app/models/auth/identity.rb)
- [app/models/auth/two_factor_authentication_provider.rb](/home/ihsan/Works/VirtualSpirit/Ruby/engines/authentication/app/models/auth/two_factor_authentication_provider.rb)
- [app/models/auth/two_factor_authentication_session.rb](/home/ihsan/Works/VirtualSpirit/Ruby/engines/authentication/app/models/auth/two_factor_authentication_session.rb)

Most real behavior is injected by decorator objects and provider modules under `lib/auth`.

### `authenticatable`

When `Auth::Models::Decorators::Authenticatable` decorates a class, the class gets:

- registration into the authenticatable registry
- `auth_config` and derived helper methods such as `auth_doorkeeper`
- token relations through `access_grants`, `access_tokens`, and `auth_applications`
- identity relations through `auth_identities`
- two-factor provider relations through `two_factor_authentication_providers`
- event publication support through `Plugins::Models::Concerns::Eventable::PublishesEvents`
- helper methods such as `two_factor_authentication_enabled?`, `omni_authentication_enabled?`, and `generate_auth_access_token`

In practice this means the application model remains the resource owner, while the engine supplies the auth wiring around it.

### `Auth::Application`

`Auth::Application` wraps Doorkeeper applications and adds an optional polymorphic `owner`.

That lets an application model own OAuth client records without introducing a separate application-specific join model.

### `Auth::AccessGrant` And `Auth::AccessToken`

These classes use the Doorkeeper ActiveRecord mixins and keep the token persistence layer under the engine namespace.

`Auth::AccessToken` also adds a polymorphic `resource_owner`, so more than one authenticatable class can share the same token table.

### `Auth::Identity`

`Auth::Identity` stores third-party provider mappings through:

- `provider`
- `uid`
- `authenticatable_type`
- `authenticatable_id`

This is the persistence point the OmniAuth config layer uses when a provider login should attach to an existing authenticatable record or create a new one.

### `Auth::TwoFactorAuthenticationProvider`

When `Auth::Models::Decorators::TwoFactorAuthenticationProvider::Object` is included, the model gets:

- a polymorphic `authenticatable`
- encrypted `secret`
- `sessions`
- provider validation against the registered provider names
- callback forwarding through `config.object.callbacks`
- `provider_class` and `provider` resolution helpers

This is the persisted configuration layer for a second-factor provider instance attached to a resource owner.

### `Auth::TwoFactorAuthenticationSession`

When `Auth::Models::Decorators::TwoFactorAuthenticationSession::Object` is included, the model gets:

- a `provider` relation
- metadata storage through `custom_attributes_definition`
- scopes for unverified, not-expired, and cooling-down sessions
- attempt counting and verification timestamps
- callback forwarding through `provider.config.session.callbacks`
- `attempt!`, `expire!`, and status helpers for the verification lifecycle

This is the persisted request/session layer for a second-factor attempt.

That distinction matters. The session is not only "the place where an OTP challenge was stored". It is the durable boundary between:

- one initiation request that started a challenge
- one or more follow-up verification requests that try to complete it
- the provider state that decides whether the session is still valid, cooling down, expired, or already verified

In practice, this means an application can initiate second-factor authentication in one request:

```ruby
provider = current_user.two_factor_authentication_providers.find_by!(name: "totp")
session = provider.provider.initiate_two_factor_authentication
```

and then verify it in a later request:

```ruby
provider = current_user.two_factor_authentication_providers.find_by!(name: "totp")
session = provider.sessions.find_by!(session_uid: params[:session_uid])

provider.provider.verify_two_factor_authentication(session, params[:code])
```

The session record is what makes that flow safe to carry across requests. It stores:

- `session_uid` for request-to-request lookup
- `started_at` and `expires_at` for validity checks
- `verified_at` for one-time completion
- `attempts` for brute-force protection
- `current_authentication` in memory during the active verification call
- metadata such as delivery status, sent count, next allowed delivery time, channel, and context

So the session model can support more than one transport style:

- TOTP verification where the provider computes the expected code from the stored secret
- SMS or email OTP verification where the initiation step sends a challenge and the verify step compares the submitted value later
- session-based login requests where the first request only starts the challenge and the second request completes the login after the client returns with `session_uid` and the second-factor value

It can also be used as a general verification-session primitive, not only as a login-second-factor primitive.

That is useful when an application has multiple verification pipelines such as:

- account confirmation
- password reset
- email-change confirmation
- phone-number verification
- privileged-action approval

Many authentication stacks model those as unrelated flows with different tokens, tables, and callbacks. `Auth::TwoFactorAuthenticationSession` gives an application one persisted session object that can be reused across those verification pipelines as long as the provider and application logic define:

- how the session is initiated
- which challenge or code is delivered
- what `metadata.context` means for the request
- what should happen after a session is successfully verified

In other words, the session model can unify the request lifecycle even when the business purpose changes. The application can treat "confirm this account", "verify this reset request", and "approve this sensitive action" as different contexts on top of the same persisted verification-session structure instead of maintaining a different token mechanism for each one.

The lifecycle helpers are built for that request-based flow:

- `attempt!` rejects verification when max attempts are reached, when the session is already verified, or when the session is expired
- `attempt!` also increments the attempt counter and stamps `verified_at` when verification succeeds
- `expire!` lets an application or provider terminate the session early
- `unverified`, `not_expired`, `with_attempts_left`, and `cooling_down` help query the still-usable challenge sessions

Because callbacks are delegated through `provider.config.session.callbacks`, applications can also attach request-flow behavior to the session layer itself, such as:

- stamping request metadata before save
- setting delivery cooldown windows
- writing transport or device context into `metadata`
- rejecting session creation for blocked authenticatables
- routing the same session primitive into confirmation, reset, or approval workflows based on `metadata.context`

That makes `Auth::TwoFactorAuthenticationSession` the main object for session-based second-factor requests. The provider defines how authentication is initiated and verified, while the session carries the persisted state that survives between those requests.

So while the engine names this surface `TwoFactorAuthenticationSession`, the actual abstraction is broader: it is a persisted verification session that can unify multiple application verification pipelines, not only a classic second-factor login flow.

## Application Expansion Model

The engine is built so the application expands it in five layers:

1. Decorate one or more application models with `authenticatable`.
2. Enable and configure Doorkeeper behavior for each authenticatable model.
3. Expose token routes for the enabled authenticatables.
4. Add identity or OmniAuth behavior where provider linkage is needed.
5. Register and configure two-factor providers when a second verification step is required.

### 1. Declare Application Authenticatable Models

The dummy app shows the intended pattern:

```ruby
class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

  authenticatable do
    doorkeeper do
      enabled true
    end
  end
end
```

This is enough to register `User` as an authenticatable model and expose the auth associations and helper methods on the class.

### 2. Configure Credential Resolution

Token routes only become useful once the application decides how credentials map back to a resource owner.

The dummy app does that like this:

```ruby
class User < ApplicationRecord
  authenticatable do
    doorkeeper do
      enabled true

      resource_owner_from_credentials do |request|
        keys = ::Devise.authentication_keys
        key = keys.find { |ak| !request.params[ak].blank? }
        user = find_for_database_authentication(login: request.params[key])

        if user && user.valid_for_authentication? { user.valid_password?(request.params[:password]) }
          user
        end
      end
    end
  end
end
```

That block is the application-owned definition of "given this token request, which authenticatable record should be treated as the resource owner?"

### 3. Expose Token Routes

Once at least one authenticatable model enables Doorkeeper, the route helper can generate token endpoints:

```ruby
Rails.application.routes.draw do
  use_doorkeeper_token_authenticatable_routes
end
```

The helper walks the authenticatable registry and adds routes only for classes whose `auth_doorkeeper.enabled` is true.

Applications can also expose one class at a time:

```ruby
Rails.application.routes.draw do
  use_doorkeeper_token_authenticatable_route(User, segment: "users")
end
```

### 4. Enable Identity Or OmniAuth Flows

If the application needs provider-linked login, the `omni_authentication` config layer controls:

- which provider names are enabled
- how the incoming auth hash is mapped
- how the authenticatable record is found or initialized
- how the `Auth::Identity` record is found or initialized
- which callbacks run before and after authentication

Example:

```ruby
class User < ApplicationRecord
  authenticatable do
    omni_authentication do
      enabled true
      providers ["google"]

      authenticatable_finder do |ctx|
        where(email: ctx.auth_hash.dig(:info, :email)).first_or_initialize
      end
    end
  end
end
```

### 5. Register Two-Factor Providers

Two-factor providers are explicit classes, not scattered callback code. The engine ships the provider DSL and a built-in TOTP implementation.

Applications can register providers at boot:

```ruby
Auth.setup do |auth|
  auth.register_two_factor_authentication_providers(
    "Auth::Providers::TwoFactorAuthentication::Totp"
  )
end
```

Then an authenticatable class can expose those providers through:

- `two_factor_authentication.enabled`
- `two_factor_authentication.providers`

## Routes And Token Endpoints

`Auth::Routes` exposes two helpers:

- `use_doorkeeper_token_authenticatable_routes`
- `use_doorkeeper_token_authenticatable_route`

For an authenticatable class named `User` with `authenticatable "user"` and the default `base_scope: "auth"` and `path: "sessions"`, the generated endpoints look like:

- `POST /auth/user/sessions`
- `POST /auth/user/sessions/refresh`
- `POST /auth/user/sessions/revoke`
- `POST /auth/user/sessions/introspect`

The exact path is shaped by:

- `base_scope`
- `segment`
- `path`
- `klass.auth_doorkeeper.default_grant_type`
- `klass.auth_doorkeeper.grant_types`

This means two authenticatable models can coexist cleanly:

```ruby
class User < ApplicationRecord
  authenticatable "user" do
    doorkeeper do
      enabled true
    end
  end
end

class AdminUser < ApplicationRecord
  authenticatable "admin" do
    doorkeeper do
      enabled true
      default_scope "admin"
    end
  end
end
```

```ruby
Rails.application.routes.draw do
  use_doorkeeper_token_authenticatable_routes
end
```

That produces separate token routes per authenticatable name instead of forcing both classes through one controller path.

## Two-Factor Authentication Providers

`Auth::Providers::TwoFactorAuthentication` is the provider DSL for second-factor implementations.

It gives provider classes:

- config storage through `config`
- annotation-based lifecycle hooks for `initiation` and `verification`
- `before_initiation`, `after_initiation`, `before_verification`, and `after_verification` callbacks
- event publication around initiation and verification
- persisted provider and session callback hooks

### Built-In TOTP Provider

The engine ships `Auth::Providers::TwoFactorAuthentication::Totp`.

It provides:

- secret generation through `ROTP::Base32.random_base32`
- configurable digits and interval
- drift-aware verification
- automatic secret generation before provider save

The default flow is:

1. create or resolve a `Auth::TwoFactorAuthenticationProvider` record for the authenticatable model
2. start a `Auth::TwoFactorAuthenticationSession` through the provider
3. generate a TOTP code on initiation
4. verify the submitted code through the session and mark the session verified on success

### Custom Two-Factor Provider Example

Applications can implement providers directly with the DSL:

```ruby
class SmsOtpProvider
  include Auth::Providers::TwoFactorAuthentication

  add_config :delivery_service, -> { SmsService }
  add_config :code_generator, -> { rand(100_000..999_999).to_s }

  configure do
    session do
      expires_in 10.minutes
      cooldown_in 30.seconds
    end
  end

  initiation do |session|
    code = config.code_generator.call
    session.metadata.channel = "sms"
    session.metadata.delivery_status = "sent"
    session.metadata.context = "login"
    config.delivery_service.call.deliver(authenticatable.phone_number, code)
    code
  end

  verification do |session, submitted_code|
    ActiveSupport::SecurityUtils.secure_compare(
      session.current_authentication.to_s,
      submitted_code.to_s
    )
  end
end
```

After registration, the persisted provider records can use the configured provider name and session callbacks without changing the engine models.

## Doorkeeper And Grape Integration

`Auth` does not ship a standalone API tree like the commerce engines. Instead, it supplies helper layers that the application can attach to Rails controllers or Grape endpoints.

### Rails Token Controller Flow

`Auth::Doorkeeper::SessionsController` inherits from `Doorkeeper::TokensController` and includes `Auth::Controllers::Concerns::DoorkeeperTokens`.

That concern handles:

- grant-type validation against the authenticatable config
- token issuance through Doorkeeper
- token revoke and introspection actions
- lookup of the authenticatable class from route defaults or params
- optional custom token response shaping through `auth_doorkeeper.custom_token_response`

### Grape Authorization Helper

`Auth::Grape::Helpers::Doorkeeper` adds:

- `doorkeeper_authenticate!`
- `doorkeeper_authenticate`
- `skip_doorkeeper_authentication!`
- `doorkeeper_current_resource_owner`

Example:

```ruby
class ProtectedApi < Grape::API
  include Auth::Grape::Helpers::Doorkeeper

  doorkeeper_authenticate! :public

  get :me do
    { id: doorkeeper_current_resource_owner.id }
  end
end
```

This keeps the auth engine focused on the authentication boundary rather than on owning an application-specific API tree.

## Configuration

The main setup entrypoint is:

```ruby
Auth.setup do |auth|
  # configuration
end
```

The main config surfaces are:

- `auth.api`
- `auth.grape_api`
- `auth.doorkeeper`
- `auth.redis`
- `auth.application_record_base`

### Doorkeeper Configuration

`Auth::Configuration::Doorkeeper` forwards to the underlying Doorkeeper configuration:

```ruby
Auth.setup do |auth|
  auth.doorkeeper.setup do |config|
    config.access_token_expires_in 2.hours
    config.default_scopes :public
    config.optional_scopes :admin
  end
end
```

Per-authenticatable defaults then read from this global Doorkeeper config unless the class overrides them.

### API And Grape Configuration

The engine also exposes the standard plugin config surfaces:

- `Auth::Configuration::Api`
- `Auth::Configuration::GrapeApi`

The default API authenticate hook is:

```ruby
Auth::Configuration::Api.authenticate = -> { User.first }
```

The default Grape authenticate hook is:

```ruby
Auth::Configuration::GrapeApi.authenticate = -> { false }
```

These are generic integration hooks. The actual auth boundary for token issuance still lives in the Doorkeeper and authenticatable configuration described above.

## What Provider And Token Hooks Actually Change

The major extension surfaces affect different layers:

- `authenticatable ... doorkeeper ...`: changes how a model issues and validates token requests
- `authenticatable ... omni_authentication ...`: changes how provider logins map into identities and authenticatable records
- `authenticatable ... two_factor_authentication ...`: changes whether and how second-factor providers are exposed
- `Auth::Providers::TwoFactorAuthentication`: changes how a provider initiates and verifies a second factor
- `Auth::Routes`: changes where token endpoints are exposed and which authenticatable classes receive them
- `Auth::Controllers::Concerns::DoorkeeperTokens`: shapes the Rails token-response lifecycle
- `Auth::Grape::Helpers::Doorkeeper`: shapes access-token enforcement inside Grape endpoints

So the engine’s extensibility is not concentrated in one model. It is split deliberately across:

- resource-owner decoration
- token-route exposure
- provider registration
- token and provider callback layers

## Dummy-App Integration Example

The dummy app demonstrates the smallest useful setup:

```ruby
class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

  authenticatable do
    doorkeeper do
      enabled true

      resource_owner_from_credentials do |request|
        keys = ::Devise.authentication_keys
        key = keys.find { |ak| !request.params[ak].blank? }
        user = find_for_database_authentication(login: request.params[key])

        if user && user.valid_for_authentication? { user.valid_password?(request.params[:password]) }
          user
        end
      end
    end
  end
end
```

```ruby
Rails.application.routes.draw do
  use_doorkeeper_token_authenticatable_routes
end
```

That setup is enough to show the engine’s intended usage pattern:

- the application keeps its own `User` model
- `authenticatable` adds the auth layer
- Doorkeeper issues the tokens
- the auth route helper exposes the token endpoints

## Notes

- `Auth::Code` exists as a placeholder surface for code-based flows, but the engine’s current implemented path is centered on Doorkeeper tokens, identities, and two-factor providers.
- the built-in provider DSL publishes initiation and verification events through the Plugins eventable concern, so applications can attach side effects without rewriting provider classes
- `Auth::AccessToken#resource_owner` is polymorphic, which is what allows multiple authenticatable classes to share the same token infrastructure

## License

The gem is available as open source under the terms of the [MIT License](MIT-LICENSE).
