module Auth
  module Models
    module Decorators
      module Authenticatable

        extend ::Plugins::Decorators::ConfigBuilder

        mattr_accessor :registered_classes
        @@registered_classes = Set.new

        def self.register_class klass
          @@registered_classes << klass
        end

        def self.registered?(klass)
          @@registered_classes.include?(klass)
        end

        def self.included base
          base.extend ClassMethods
        end

        def self.default_options
          defaults = {
            name: nil,
            native_provider: nil,
            doorkeeper: config_builder(**{
              grant_types: ["password", "refresh_token"],
              default_grant_type: proc { auth_config.doorkeeper.grant_types[0] },
              allowed_scopes: proc { (::Auth.config.doorkeeper.config.default_scopes.to_a + ::Auth.config.doorkeeper.config.optional_scopes.to_a).join(" ") },
              default_scope: proc { ::Auth.config.doorkeeper.config.default_scopes },
              enabled: false,
              resource_owner_authenticator: proc { nil },
              resource_owner_from_credentials: proc {|request| nil },
              jwt_payload: proc {
                as_json
              },
              access_token_expires_in: proc {
                ::Auth.config.doorkeeper.config.access_token_expires_in
              }
            }),
            two_factor_authentication: config_builder(**{
              enabled: proc {
                auth_two_factor_authentication.providers.enabled.exists?
              },
              providers: :two_factor_authentication_providers,
            }),
            omni_authentication: config_builder(**{
              enabled: false,
              providers: ["google", "facebook"],
              auth_hash_mapping: proc { |auth_hash|
                auth_hash
              },
              authenticatable_finder: proc{|ctx|
                where(email: ctx.auth_hash.dig(:info, :email)).first_or_initialize
              },
              identity_finder: proc { |ctx|
                Auth::Identity.where(provider: ctx.provider_name, uid: ctx.auth_hash[:uid]).first_or_initialize
              },
              before_authenticate: proc { |ctx|
                publish_event('before_omniauth_authentication', bus: :auth, prefix: 'auth', auth_hash: ctx.auth_hash)
              },
              authenticate: proc { |ctx|
                identity = ctx.identity
                save if new_record?
                if persisted? && identity.new_record?
                  identity.info = ctx.auth_hash[:info]
                  identity.authenticatable = self
                  identity.save
                end
                identity
              },
              after_authenticate: proc { |provider_name, mapped_auth_hash, ctx|
                publish_event('after_omniauth_authentication', bus: :auth, prefix: 'auth', object: identity)
              },
              token_verifier: "auto" # or the name of the class, etc
            }),

          }
          defaults
        end

        module ClassMethods

          def authenticatable *args, &block
            opts = args.extract_options!
            auth_name = args[0] || self.name.demodulize.downcase.underscore
            opts[:name] = auth_name

            opts[:provider_name] ||= get_auth_native_prodiver_name

            ::Auth::Models::Decorators::Authenticatable.config_class.setup(self, 'auth_config', opts, ::Auth::Models::Decorators::Authenticatable.default_options, method_prefix: "auth", &block)

            authenticatable_include_modules

            ::Auth::Models::Decorators::Authenticatable.register_class(self)

          end

          def inherited(sub)
            super(sub)
            if ::Auth::Models::Decorators::Authenticatable.registered?(self)
              ::Auth::Models::Decorators::Authenticatable.register_class(sub)
            end
          end

          private

          def get_auth_native_prodiver_name
            "devise"
          end

          def authenticatable_include_modules
            include DepedencyModules
            include OmniAuthResources
            include TwoFactorAuthResources
            include DoorkeeperResources
          end

        end

        module InstanceMethods

          def two_factor_authentication_enabled?
            auth_two_factor_authentication.enabled
          end

          def omni_authentication_enabled?
            auth_omni_authentication.enabled
          end

        end

        module DepedencyModules
          extend ActiveSupport::Concern
          included do
            include ::Plugins::Models::Concerns::Eventable::PublishesEvents
            include InstanceMethods
          end
        end

        module OmniAuthResources
          extend ActiveSupport::Concern
          included do
            has_many :auth_identities,
              class_name: "Auth::Identity",
              as: :authenticatable,
              dependent: :destroy
          end
        end

        module TwoFactorAuthResources
          extend ActiveSupport::Concern
          included do
            has_many :two_factor_authentication_providers,
              class_name: "Auth::TwoFactorAuthenticationProvider",
              as: :authenticatable,
              dependent: :destroy
          end
        end

        module DoorkeeperResources
          extend ActiveSupport::Concern
          included do
            has_many :access_grants,
              class_name: 'Auth::AccessGrant',
              as: :resource_owner,
              dependent: :destroy

            has_many :access_tokens,
              class_name: 'Auth::AccessToken',
              as: :resource_owner,
              dependent: :destroy

            has_many :auth_applications,
              class_name: 'Auth::Application',
              as: :owner,
              dependent: :destroy
          end

          def generate_auth_access_token(app=nil, scopes=auth_doorkeeper.default_scope)
            ::Auth::AccessToken.create(
              application: app,
              resource_owner_id: self.id,
              resource_owner_type: self.class.name,
              refresh_token: generate_refresh_token,
              expires_in: auth_doorkeeper.access_token_expires_in.to_i,
              scopes: scopes
            )
          end

          def generate_refresh_token
            loop do
              token = SecureRandom.hex(32)
              break token unless ::Doorkeeper::AccessToken.exists?(refresh_token: token)
            end
          end

        end

      end
    end
  end
end