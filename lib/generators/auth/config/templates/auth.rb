Auth.setup do |auth|

  #auth.devise_routes_enabled = true

  # auth.resources = { accounts: {class_name: "Auth::Account", path: "accounts", module: :devise} }
  # uncomment this if two factor auth will be enabled
  #auth.resources = { accounts: {class_name: "Auth::Account", controllers: { sessions: 'auth/sessions'}, path: "accounts", module: :devise} }

  #auth.doorkeeper_enabled = true

  auth.devise_default_modules = [:database_authenticatable, :registerable, :recoverable, :rememberable, :validatable, :confirmable]
  # uncomment this if two factor auth will be enabled
  # config.devise_default_modules = [
  #   :registerable,
  #   :recoverable,
  #   :rememberable,
  #   :validatable,
  #   :confirmable,
  #   :two_factor_authenticatable, :two_factor_backupable,
  #   otp_digits_length: 4, otp_allowed_drift: 60,
  #   otp_backup_code_length: 5, otp_number_of_backup_codes: 5,
  #   :otp_secret_encryption_key => ENV['OTP_SECRET_KEY']
  # ]


  auth.devise_setup do |config|

    # two factor authentication is enabled
    # uncomment this
    # config.sign_in_after_reset_password = false
    # config.warden do |manager|
    #   manager.default_strategies(:scope => :auth_account).unshift :two_factor_backupable
    #   manager.default_strategies(:scope => :auth_account).unshift :two_factor_authenticatable
    # end

    # The secret key used by Devise. Devise uses this key to generate
    # random tokens. Changing this key will render invalid all existing
    # confirmation, reset password and unlock tokens in the database.
    # Devise will use the `secret_key_base` as its `secret_key`
    # by default. You can change it below and use your own secret key.
    # config.secret_key = '1cb98a94e074491ee0014fe5797e8f67e12afdf5b5fc950d8e6a09f2e9eb595c0d4d2842d9673c316901e73da740d944a178a13ab4a2f439826a457fe5dd587e'

    # ==> Controller configuration
    # Configure the parent class to the devise controllers.
    config.parent_controller = 'Auth::ApplicationController'

    # ==> Mailer Configuration
    # Configure the e-mail address which will be shown in Devise::Mailer,
    # note that it will be overwritten if you use your own mailer class
    # with default "from" parameter.
    config.mailer_sender = 'admin@devise.com'

    # Configure the class responsible to send e-mails.
    # config.mailer = 'Devise::Mailer'

    # Configure the parent class responsible to send e-mails.
    # config.parent_mailer = 'ActionMailer::Base'

    # ==> ORM configuration
    # Load and configure the ORM. Supports :active_record (default) and
    # :mongoid (bson_ext recommended) by default. Other ORMs may be
    # available as additional gems.
    require 'devise/orm/active_record'

    # ==> Configuration for any authentication mechanism
    # Configure which keys are used when authenticating a user. The default is
    # just :email. You can configure it to use [:username, :subdomain], so for
    # authenticating a user, both parameters are required. Remember that those
    # parameters are used only when authenticating and not when retrieving from
    # session. If you need permissions, you should implement that in a before filter.
    # You can also supply a hash where the value is a boolean determining whether
    # or not authentication should be aborted when the value is not present.
    # config.authentication_keys = [:email]

    # Configure parameters from the request object used for authentication. Each entry
    # given should be a request method and it will automatically be passed to the
    # find_for_authentication method and considered in your model lookup. For instance,
    # if you set :request_keys to [:subdomain], :subdomain will be used on authentication.
    # The same considerations mentioned for authentication_keys also apply to request_keys.
    # config.request_keys = []

    # Configure which authentication keys should be case-insensitive.
    # These keys will be downcased upon creating or modifying a user and when used
    # to authenticate or find a user. Default is :email.
    config.case_insensitive_keys = [:email]

    # Configure which authentication keys should have whitespace stripped.
    # These keys will have whitespace before and after removed upon creating or
    # modifying a user and when used to authenticate or find a user. Default is :email.
    config.strip_whitespace_keys = [:email]

    # Tell if authentication through request.params is enabled. True by default.
    # It can be set to an array that will enable params authentication only for the
    # given strategies, for example, `config.params_authenticatable = [:database]` will
    # enable it only for database (email + password) authentication.
    # config.params_authenticatable = true

    # Tell if authentication through HTTP Auth is enabled. False by default.
    # It can be set to an array that will enable http authentication only for the
    # given strategies, for example, `config.http_authenticatable = [:database]` will
    # enable it only for database authentication.
    # For API-only applications to support authentication "out-of-the-box", you will likely want to
    # enable this with :database unless you are using a custom strategy.
    # The supported strategies are:
    # :database      = Support basic authentication with authentication key + password
    # config.http_authenticatable = false

    # If 401 status code should be returned for AJAX requests. True by default.
    # config.http_authenticatable_on_xhr = true

    # The realm used in Http Basic Authentication. 'Application' by default.
    # config.http_authentication_realm = 'Application'

    # It will change confirmation, password recovery and other workflows
    # to behave the same regardless if the e-mail provided was right or wrong.
    # Does not affect registerable.
    # config.paranoid = true

    # By default Devise will store the user in session. You can skip storage for
    # particular strategies by setting this option.
    # Notice that if you are skipping storage for all authentication paths, you
    # may want to disable generating routes to Devise's sessions controller by
    # passing skip: :sessions to `devise_for` in your config/routes.rb
    config.skip_session_storage = [:http_auth]

    # By default, Devise cleans up the CSRF token on authentication to
    # avoid CSRF token fixation attacks. This means that, when using AJAX
    # requests for sign in and sign up, you need to get a new CSRF token
    # from the server. You can disable this option at your own risk.
    # config.clean_up_csrf_token_on_authentication = true

    # When false, Devise will not attempt to reload routes on eager load.
    # This can reduce the time taken to boot the app but if your application
    # requires the Devise mappings to be loaded during boot time the application
    # won't boot properly.
    # config.reload_routes = true

    # ==> Configuration for :database_authenticatable
    # For bcrypt, this is the cost for hashing the password and defaults to 12. If
    # using other algorithms, it sets how many times you want the password to be hashed.
    # The number of stretches used for generating the hashed password are stored
    # with the hashed password. This allows you to change the stretches without
    # invalidating existing passwords.
    #
    # Limiting the stretches to just one in testing will increase the performance of
    # your test suite dramatically. However, it is STRONGLY RECOMMENDED to not use
    # a value less than 10 in other environments. Note that, for bcrypt (the default
    # algorithm), the cost increases exponentially with the number of stretches (e.g.
    # a value of 20 is already extremely slow: approx. 60 seconds for 1 calculation).
    config.stretches = Rails.env.test? ? 1 : 12

    # Set up a pepper to generate the hashed password.
    # config.pepper = 'feb93f90d5a3b981f3ad4425ce018a120de62599b24004244de87821135dcf8887bc56cb3e26b5d8f9a2b7aa5d823276731418926241c1d5997898f4f0b009e0'

    # Send a notification to the original email when the user's email is changed.
    # config.send_email_changed_notification = false

    # Send a notification email when the user's password is changed.
    # config.send_password_change_notification = false

    # ==> Configuration for :confirmable
    # A period that the user is allowed to access the website even without
    # confirming their account. For instance, if set to 2.days, the user will be
    # able to access the website for two days without confirming their account,
    # access will be blocked just in the third day.
    # You can also set it to nil, which will allow the user to access the website
    # without confirming their account.
    # Default is 0.days, meaning the user cannot access the website without
    # confirming their account.
    # config.allow_unconfirmed_access_for = 2.days

    # A period that the user is allowed to confirm their account before their
    # token becomes invalid. For example, if set to 3.days, the user can confirm
    # their account within 3 days after the mail was sent, but on the fourth day
    # their account can't be confirmed with the token any more.
    # Default is nil, meaning there is no restriction on how long a user can take
    # before confirming their account.
    # config.confirm_within = 3.days

    # If true, requires any email changes to be confirmed (exactly the same way as
    # initial account confirmation) to be applied. Requires additional unconfirmed_email
    # db field (see migrations). Until confirmed, new email is stored in
    # unconfirmed_email column, and copied to email column on successful confirmation.
    config.reconfirmable = true

    # Defines which key will be used when confirming an account
    # config.confirmation_keys = [:email]

    # ==> Configuration for :rememberable
    # The time the user will be remembered without asking for credentials again.
    # config.remember_for = 2.weeks

    # Invalidates all the remember me tokens when the user signs out.
    config.expire_all_remember_me_on_sign_out = true

    # If true, extends the user's remember period when remembered via cookie.
    # config.extend_remember_period = false

    # Options to be passed to the created cookie. For instance, you can set
    # secure: true in order to force SSL only cookies.
    # config.rememberable_options = {}

    # ==> Configuration for :validatable
    # Range for password length.
    config.password_length = 6..128

    # Email regex used to validate email formats. It simply asserts that
    # one (and only one) @ exists in the given string. This is mainly
    # to give user feedback and not to assert the e-mail validity.
    config.email_regexp = /\A[^@\s]+@[^@\s]+\z/

    # ==> Configuration for :timeoutable
    # The time you want to timeout the user session without activity. After this
    # time the user will be asked for credentials again. Default is 30 minutes.
    # config.timeout_in = 30.minutes

    # ==> Configuration for :lockable
    # Defines which strategy will be used to lock an account.
    # :failed_attempts = Locks an account after a number of failed attempts to sign in.
    # :none            = No lock strategy. You should handle locking by yourself.
    # config.lock_strategy = :failed_attempts

    # Defines which key will be used when locking and unlocking an account
    # config.unlock_keys = [:email]

    # Defines which strategy will be used to unlock an account.
    # :email = Sends an unlock link to the user email
    # :time  = Re-enables login after a certain amount of time (see :unlock_in below)
    # :both  = Enables both strategies
    # :none  = No unlock strategy. You should handle unlocking by yourself.
    # config.unlock_strategy = :both

    # Number of authentication tries before locking an account if lock_strategy
    # is failed attempts.
    # config.maximum_attempts = 20

    # Time interval to unlock the account if :time is enabled as unlock_strategy.
    # config.unlock_in = 1.hour

    # Warn on the last attempt before the account is locked.
    # config.last_attempt_warning = true

    # ==> Configuration for :recoverable
    #
    # Defines which key will be used when recovering the password for an account
    # config.reset_password_keys = [:email]

    # Time interval you can reset your password with a reset password key.
    # Don't put a too small interval or your users won't have the time to
    # change their passwords.
    config.reset_password_within = 6.hours

    # When set to false, does not sign a user in automatically after their password is
    # reset. Defaults to true, so a user is signed in automatically after a reset.
    # config.sign_in_after_reset_password = true\

    # ==> Configuration for :encryptable
    # Allow you to use another hashing or encryption algorithm besides bcrypt (default).
    # You can use :sha1, :sha512 or algorithms from others authentication tools as
    # :clearance_sha1, :authlogic_sha512 (then you should set stretches above to 20
    # for default behavior) and :restful_authentication_sha1 (then you should set
    # stretches to 10, and copy REST_AUTH_SITE_KEY to pepper).
    #
    # Require the `devise-encryptable` gem when using anything other than bcrypt
    # config.encryptor = :sha512

    # ==> Scopes configuration
    # Turn scoped views on. Before rendering "sessions/new", it will first check for
    # "users/sessions/new". It's turned off by default because it's slower if you
    # are using only default views.
    # config.scoped_views = false

    # Configure the default scope given to Warden. By default it's the first
    # devise role declared in your routes (usually :user).
    # config.default_scope = :user

    # Set this configuration to false if you want /users/sign_out to sign out
    # only the current scope. By default, Devise signs out all scopes.
    # config.sign_out_all_scopes = true

    # ==> Navigation configuration
    # Lists the formats that should be treated as navigational. Formats like
    # :html, should redirect to the sign in page when the user does not have
    # access, but formats like :xml or :json, should return 401.
    #
    # If you have any extra navigational formats, like :iphone or :mobile, you
    # should add them to the navigational formats lists.
    #
    # The "*/*" below is required to match Internet Explorer requests.
    # config.navigational_formats = ['*/*', :html]

    # The default HTTP method used to sign out a resource. Default is :delete.
    config.sign_out_via = :delete

    # ==> OmniAuth
    # Add a new OmniAuth provider. Check the wiki for more information on setting
    # up on your models and hooks.
    # config.omniauth :github, 'APP_ID', 'APP_SECRET', scope: 'user,public_repo'

    # ==> Warden configuration
    # If you want to use other strategies, that are not supported by Devise, or
    # change the failure app, you can configure them inside the config.warden block.
    #
    # config.warden do |manager|
    #   manager.intercept_401 = false
    #   manager.default_strategies(scope: :user).unshift :some_external_strategy
    # end

    # ==> Mountable engine configurations
    # When using Devise inside an engine, let's call it `MyEngine`, and this engine
    # is mountable, there are some extra configurations to be taken into account.
    # The following options are available, assuming the engine is mounted as:
    #
    #     mount MyEngine, at: '/my_engine'
    #
    # The router that invoked `devise_for`, in the example above, would be:
    config.router_name = :auth
    #
    # When using OmniAuth, Devise cannot automatically set OmniAuth path,
    # so you need to do it manually. For the users scope, it would be:
    # config.omniauth_path_prefix = '/my_engine/users/auth'

    # ==> Turbolinks configuration
    # If your app is using Turbolinks, Turbolinks::Controller needs to be included to make redirection work correctly:
    #
    # ActiveSupport.on_load(:devise_failure_app) do
    #   include Turbolinks::Controller
    # end

    # ==> Configuration for :registerable

    # When set to false, does not sign a user in automatically after their password is
    # changed. Defaults to true, so a user is signed in automatically after changing a password.
    # config.sign_in_after_change_password = true
  end

  auth.doorkeeper_setup do |config|
    # Change the ORM that doorkeeper will use (requires ORM extensions installed).
    # Check the list of supported ORMs here: https://github.com/doorkeeper-gem/doorkeeper#orms
    orm :active_record

    # This block will be called to check whether the resource owner is authenticated or not.
    resource_owner_authenticator do
      current_user || warden.authenticate!(scope: :user)
      #raise "Please configure doorkeeper resource_owner_authenticator block located in #{__FILE__}"
      # Put your resource owner authentication logic here.
      # Example implementation:
      #   User.find_by(id: session[:user_id]) || redirect_to(new_user_session_url)
    end

    resource_owner_from_credentials do |routes|
      begin
        ResourceOwnerCredential.authenticate!(routes.request)
      rescue => e
        user=nil
      end
    end

    # If you didn't skip applications controller from Doorkeeper routes in your application routes.rb
    # file then you need to declare this block in order to restrict access to the web interface for
    # adding oauth authorized applications. In other case it will return 403 Forbidden response
    # every time somebody will try to access the admin web interface.
    #
    # admin_authenticator do
    #   # Put your admin authentication logic here.
    #   # Example implementation:
    #
    #   if current_user
    #     head :forbidden unless current_user.admin?
    #   else
    #     redirect_to sign_in_url
    #   end
    # end

    # You can use your own model classes if you need to extend (or even override) default
    # Doorkeeper models such as `Application`, `AccessToken` and `AccessGrant.
    #
    # Be default Doorkeeper ActiveRecord ORM uses it's own classes:
    #
    # access_token_class "Doorkeeper::AccessToken"
    # access_grant_class "Doorkeeper::AccessGrant"
    # application_class "Doorkeeper::Application"
    #
    # Don't forget to include Doorkeeper ORM mixins into your custom models:
    #
    #   *  ::Doorkeeper::Orm::ActiveRecord::Mixins::AccessToken - for access token
    #   *  ::Doorkeeper::Orm::ActiveRecord::Mixins::AccessGrant - for access grant
    #   *  ::Doorkeeper::Orm::ActiveRecord::Mixins::Application - for application (OAuth2 clients)
    #
    # For example:
    #
    # access_token_class "MyAccessToken"
    #
    # class MyAccessToken < ApplicationRecord
    #   include ::Doorkeeper::Orm::ActiveRecord::Mixins::AccessToken
    #
    #   self.table_name = "hey_i_wanna_my_name"
    #
    #   def destroy_me!
    #     destroy
    #   end
    # end

    # If you are planning to use Doorkeeper in Rails 5 API-only application, then you might
    # want to use API mode that will skip all the views management and change the way how
    # Doorkeeper responds to a requests.
    #
    api_only

    # Enforce token request content type to application/x-www-form-urlencoded.
    # It is not enabled by default to not break prior versions of the gem.
    #
    # enforce_content_type

    # Authorization Code expiration time (default: 10 minutes).
    #
    # authorization_code_expires_in 10.minutes

    # Access token expiration time (default: 2 hours).
    # If you want to disable expiration, set this to `nil`.
    #
    # access_token_expires_in 2.hours

    # Assign custom TTL for access tokens. Will be used instead of access_token_expires_in
    # option if defined. In case the block returns `nil` value Doorkeeper fallbacks to
    # +access_token_expires_in+ configuration option value. If you really need to issue a
    # non-expiring access token (which is not recommended) then you need to return
    # Float::INFINITY from this block.
    #
    # `context` has the following properties available:
    #
    # `client` - the OAuth client application (see Doorkeeper::OAuth::Client)
    # `grant_type` - the grant type of the request (see Doorkeeper::OAuth)
    # `scopes` - the requested scopes (see Doorkeeper::OAuth::Scopes)
    #
    # custom_access_token_expires_in do |context|
    #   context.client.application.additional_settings.implicit_oauth_expiration
    # end

    # Use a custom class for generating the access token.
    # See https://doorkeeper.gitbook.io/guides/configuration/other-configurations#custom-access-token-generator
    #
    # access_token_generator '::Doorkeeper::JWT'

    # The controller +Doorkeeper::ApplicationController+ inherits from.
    # Defaults to +ActionController::Base+ unless +api_only+ is set, which changes the default to
    # +ActionController::API+. The return value of this option must be a stringified class name.
    # See https://doorkeeper.gitbook.io/guides/configuration/other-configurations#custom-base-controller
    #
    # base_controller 'ApplicationController'
    base_controller 'ActionController::API'

    # Reuse access token for the same resource owner within an application (disabled by default).
    #
    # This option protects your application from creating new tokens before old valid one becomes
    # expired so your database doesn't bloat. Keep in mind that when this option is `on` Doorkeeper
    # doesn't updates existing token expiration time, it will create a new token instead.
    # Rationale: https://github.com/doorkeeper-gem/doorkeeper/issues/383
    #
    # You can not enable this option together with +hash_token_secrets+.
    #
    # reuse_access_token

    # In case you enabled `reuse_access_token` option Doorkeeper will try to find matching
    # token using `matching_token_for` Access Token API that searches for valid records
    # in batches in order not to pollute the memory with all the database records. By default
    # Doorkeeper uses batch size of 10 000 records. You can increase or decrease this value
    # depending on your needs and server capabilities.
    #
    # token_lookup_batch_size 10_000

    # Set a limit for token_reuse if using reuse_access_token option
    #
    # This option limits token_reusability to some extent.
    # If not set then access_token will be reused unless it expires.
    # Rationale: https://github.com/doorkeeper-gem/doorkeeper/issues/1189
    #
    # This option should be a percentage(i.e. (0,100])
    #
    # token_reuse_limit 100

    # Only allow one valid access token obtained via client credentials
    # per client. If a new access token is obtained before the old one
    # expired, the old one gets revoked (disabled by default)
    #
    # When enabling this option, make sure that you do not expect multiple processes
    # using the same credentials at the same time (e.g. web servers spanning
    # multiple machines and/or processes).
    #
    # revoke_previous_client_credentials_token

    # Hash access and refresh tokens before persisting them.
    # This will disable the possibility to use +reuse_access_token+
    # since plain values can no longer be retrieved.
    #
    # Note: If you are already a user of doorkeeper and have existing tokens
    # in your installation, they will be invalid without enabling the additional
    # setting `fallback_to_plain_secrets` below.
    #
    # hash_token_secrets
    # By default, token secrets will be hashed using the
    # +Doorkeeper::Hashing::SHA256+ strategy.
    #
    # If you wish to use another hashing implementation, you can override
    # this strategy as follows:
    #
    # hash_token_secrets using: '::Doorkeeper::Hashing::MyCustomHashImpl'
    #
    # Keep in mind that changing the hashing function will invalidate all existing
    # secrets, if there are any.

    # Hash application secrets before persisting them.
    #
    # hash_application_secrets
    #
    # By default, applications will be hashed
    # with the +Doorkeeper::SecretStoring::SHA256+ strategy.
    #
    # If you wish to use bcrypt for application secret hashing, uncomment
    # this line instead:
    #
    # hash_application_secrets using: '::Doorkeeper::SecretStoring::BCrypt'

    # When the above option is enabled, and a hashed token or secret is not found,
    # you can allow to fall back to another strategy. For users upgrading
    # doorkeeper and wishing to enable hashing, you will probably want to enable
    # the fallback to plain tokens.
    #
    # This will ensure that old access tokens and secrets
    # will remain valid even if the hashing above is enabled.
    #
    # fallback_to_plain_secrets

    # Issue access tokens with refresh token (disabled by default), you may also
    # pass a block which accepts `context` to customize when to give a refresh
    # token or not. Similar to +custom_access_token_expires_in+, `context` has
    # the following properties:
    #
    # `client` - the OAuth client application (see Doorkeeper::OAuth::Client)
    # `grant_type` - the grant type of the request (see Doorkeeper::OAuth)
    # `scopes` - the requested scopes (see Doorkeeper::OAuth::Scopes)
    #
    use_refresh_token

    # Provide support for an owner to be assigned to each registered application (disabled by default)
    # Optional parameter confirmation: true (default: false) if you want to enforce ownership of
    # a registered application
    # NOTE: you must also run the rails g doorkeeper:application_owner generator
    # to provide the necessary support
    #
    # enable_application_owner confirmation: false

    # Define access token scopes for your provider
    # For more information go to
    # https://doorkeeper.gitbook.io/guides/ruby-on-rails/scopes
    #
    # default_scopes  :public
    # optional_scopes :write, :update

    # Allows to restrict only certain scopes for grant_type.
    # By default, all the scopes will be available for all the grant types.
    #
    # Keys to this hash should be the name of grant_type and
    # values should be the array of scopes for that grant type.
    # Note: scopes should be from configured_scopes (i.e. default or optional)
    #
    # scopes_by_grant_type password: [:write], client_credentials: [:update]

    # Forbids creating/updating applications with arbitrary scopes that are
    # not in configuration, i.e. +default_scopes+ or +optional_scopes+.
    # (disabled by default)
    #
    # enforce_configured_scopes

    # Change the way client credentials are retrieved from the request object.
    # By default it retrieves first from the `HTTP_AUTHORIZATION` header, then
    # falls back to the `:client_id` and `:client_secret` params from the `params` object.
    # Check out https://github.com/doorkeeper-gem/doorkeeper/wiki/Changing-how-clients-are-authenticated
    # for more information on customization
    #
    # client_credentials :from_basic, :from_params

    # Change the way access token is authenticated from the request object.
    # By default it retrieves first from the `HTTP_AUTHORIZATION` header, then
    # falls back to the `:access_token` or `:bearer_token` params from the `params` object.
    # Check out https://github.com/doorkeeper-gem/doorkeeper/wiki/Changing-how-clients-are-authenticated
    # for more information on customization
    #
    # access_token_methods :from_bearer_authorization, :from_access_token_param, :from_bearer_param

    # Forces the usage of the HTTPS protocol in non-native redirect uris (enabled
    # by default in non-development environments). OAuth2 delegates security in
    # communication to the HTTPS protocol so it is wise to keep this enabled.
    #
    # Callable objects such as proc, lambda, block or any object that responds to
    # #call can be used in order to allow conditional checks (to allow non-SSL
    # redirects to localhost for example).
    #
    # force_ssl_in_redirect_uri !Rails.env.development?
    #
    # force_ssl_in_redirect_uri { |uri| uri.host != 'localhost' }

    # Specify what redirect URI's you want to block during Application creation.
    # Any redirect URI is whitelisted by default.
    #
    # You can use this option in order to forbid URI's with 'javascript' scheme
    # for example.
    #
    # forbid_redirect_uri { |uri| uri.scheme.to_s.downcase == 'javascript' }

    # Allows to set blank redirect URIs for Applications in case Doorkeeper configured
    # to use URI-less OAuth grant flows like Client Credentials or Resource Owner
    # Password Credentials. The option is on by default and checks configured grant
    # types, but you **need** to manually drop `NOT NULL` constraint from `redirect_uri`
    # column for `oauth_applications` database table.
    #
    # You can completely disable this feature with:
    #
    allow_blank_redirect_uri true
    #
    # Or you can define your custom check:
    #
    # allow_blank_redirect_uri do |grant_flows, client|
    #   client.superapp?
    # end

    # Specify how authorization errors should be handled.
    # By default, doorkeeper renders json errors when access token
    # is invalid, expired, revoked or has invalid scopes.
    #
    # If you want to render error response yourself (i.e. rescue exceptions),
    # set +handle_auth_errors+ to `:raise` and rescue Doorkeeper::Errors::InvalidToken
    # or following specific errors:
    #
    #   Doorkeeper::Errors::TokenForbidden, Doorkeeper::Errors::TokenExpired,
    #   Doorkeeper::Errors::TokenRevoked, Doorkeeper::Errors::TokenUnknown
    #
    # handle_auth_errors :raise

    # Customize token introspection response.
    # Allows to add your own fields to default one that are required by the OAuth spec
    # for the introspection response. It could be `sub`, `aud` and so on.
    # This configuration option can be a proc, lambda or any Ruby object responds
    # to `.call` method and result of it's invocation must be a Hash.
    #
    # custom_introspection_response do |token, context|
    #   {
    #     "sub": "Z5O3upPC88QrAjx00dis",
    #     "aud": "https://protected.example.net/resource",
    #     "username": User.find(token.resource_owner_id).username
    #   }
    # end
    #
    # or
    #
    # custom_introspection_response CustomIntrospectionResponder

    # Specify what grant flows are enabled in array of Strings. The valid
    # strings and the flows they enable are:
    #
    # "authorization_code" => Authorization Code Grant Flow
    # "implicit"           => Implicit Grant Flow
    # "password"           => Resource Owner Password Credentials Grant Flow
    # "client_credentials" => Client Credentials Grant Flow
    #
    # If not specified, Doorkeeper enables authorization_code and
    # client_credentials.
    #
    # implicit and password grant flows have risks that you should understand
    # before enabling:
    #   http://tools.ietf.org/html/rfc6819#section-4.4.2
    #   http://tools.ietf.org/html/rfc6819#section-4.4.3
    #
    #grant_flows %w[authorization_code client_credentials]
    grant_flows %w[password]

    # Allows to customize OAuth grant flows that +each+ application support.
    # You can configure a custom block (or use a class respond to `#call`) that must
    # return `true` in case Application instance supports requested OAuth grant flow
    # during the authorization request to the server. This configuration +doesn't+
    # set flows per application, it only allows to check if application supports
    # specific grant flow.
    #
    # For example you can add an additional database column to `oauth_applications` table,
    # say `t.array :grant_flows, default: []`, and store allowed grant flows that can
    # be used with this application there. Then when authorization requested Doorkeeper
    # will call this block to check if specific Application (passed with client_id and/or
    # client_secret) is allowed to perform the request for the specific grant type
    # (authorization, password, client_credentials, etc).
    #
    # Example of the block:
    #
    #   ->(flow, client) { client.grant_flows.include?(flow) }
    #
    # In case this option invocation result is `false`, Doorkeeper server returns
    # :unauthorized_client error and stops the request.
    #
    # @param allow_grant_flow_for_client [Proc] Block or any object respond to #call
    # @return [Boolean] `true` if allow or `false` if forbid the request
    #
    # allow_grant_flow_for_client do |grant_flow, client|
    #   # `grant_flows` is an Array column with grant
    #   # flows that application supports
    #
    #   client.grant_flows.include?(grant_flow)
    # end

    # Hook into the strategies' request & response life-cycle in case your
    # application needs advanced customization or logging:
    #
    # before_successful_strategy_response do |request|
    #   puts "BEFORE HOOK FIRED! #{request}"
    # end
    #
    # after_successful_strategy_response do |request, response|
    #   puts "AFTER HOOK FIRED! #{request}, #{response}"
    # end

    # Hook into Authorization flow in order to implement Single Sign Out
    # or add any other functionality.
    #
    # before_successful_authorization do |controller|
    #   Rails.logger.info(controller.request.params.inspect)
    # end
    #
    # after_successful_authorization do |controller|
    #   controller.session[:logout_urls] <<
    #     Doorkeeper::Application
    #       .find_by(controller.request.params.slice(:redirect_uri))
    #       .logout_uri
    # end

    # Under some circumstances you might want to have applications auto-approved,
    # so that the user skips the authorization step.
    # For example if dealing with a trusted application.
    #
    # skip_authorization do |resource_owner, client|
    #   client.superapp? or resource_owner.admin?
    # end
    skip_authorization do |resource_owner, client|
      true
    end

    skip_client_authentication_for_password_grant true

    # Configure custom constraints for the Token Introspection request.
    # By default this configuration option allows to introspect a token by another
    # token of the same application, OR to introspect the token that belongs to
    # authorized client (from authenticated client) OR when token doesn't
    # belong to any client (public token). Otherwise requester has no access to the
    # introspection and it will return response as stated in the RFC.
    #
    # Block arguments:
    #
    # @param token [Doorkeeper::AccessToken]
    #   token to be introspected
    #
    # @param authorized_client [Doorkeeper::Application]
    #   authorized client (if request is authorized using Basic auth with
    #   Client Credentials for example)
    #
    # @param authorized_token [Doorkeeper::AccessToken]
    #   Bearer token used to authorize the request
    #
    # In case the block returns `nil` or `false` introspection responses with 401 status code
    # when using authorized token to introspect, or you'll get 200 with { "active": false } body
    # when using authorized client to introspect as stated in the
    # RFC 7662 section 2.2. Introspection Response.
    #
    # Using with caution:
    # Keep in mind that these three parameters pass to block can be nil as following case:
    #  `authorized_client` is nil if and only if `authorized_token` is present, and vice versa.
    #  `token` will be nil if and only if `authorized_token` is present.
    # So remember to use `&` or check if it is present before calling method on
    # them to make sure you doesn't get NoMethodError exception.
    #
    # You can define your custom check:
    #
    # allow_token_introspection do |token, authorized_client, authorized_token|
    #   if authorized_token
    #     # customize: require `introspection` scope
    #     authorized_token.application == token&.application ||
    #       authorized_token.scopes.include?("introspection")
    #   elsif token.application
    #     # `protected_resource` is a new database boolean column, for example
    #     authorized_client == token.application || authorized_client.protected_resource?
    #   else
    #     # public token (when token.application is nil, token doesn't belong to any application)
    #     true
    #   end
    # end
    #
    # Or you can completely disable any token introspection:
    #
    # allow_token_introspection false
    #
    # If you need to block the request at all, then configure your routes.rb or web-server
    # like nginx to forbid the request.

    # WWW-Authenticate Realm (default: "Doorkeeper").
    #
    # realm "Doorkeeper"
  end

  auth.enable_jwt

  auth.jwt.configure do
    token_payload do |opts|
      account = User.find(opts[:resource_owner_id])
      {
        iss: "App",
        iat: Time.current.utc.to_i,
        jti: SecureRandom.uuid,
        user: {
          id: account.id,
          email: account.email
        }
      }
    end
    use_application_secret false
    secret_key Rails.application.secret_key_base
    encryption_method :hs512
  end

end

