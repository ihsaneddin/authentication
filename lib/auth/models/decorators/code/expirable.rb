module Auth
  module Models
    module Decorators
      module Code
        module Expirable

          extend ::Auth::Models::Decorators::Code::Object

          def self.default_options
            {
              column: "expires_at",       # Attribute name for expiration time
              expires_in: 5.minutes,      # Default TTL
              grace_period: 0.seconds,    # Time window after expiration still valid
              auto_extend: false,         # Auto-extend expiration on access
              on_expire: nil,             # Callback on expiration
              touch_on_access: false      # Refresh expiration on access
            }
          end

          def self.included(base)
            base.extend ClassMethods
          end

          module ClassMethods

            def expirable(**opts, &block)
              ::Auth::Models::Decorators::Code::Object.config_class.setup(
                self,
                'expirable_config',
                opts,
                ::Auth::Models::Decorators::Code::Expirable.default_options,
                method_prefix: "expirable",
                &block
              )

              attribute expirable_column.to_sym, :datetime

              validates expirable_column, presence: true

              define_inheritable_singleton_method(:expirable?) { true }

              include InstanceMethods
            end

          end

          module InstanceMethods
            extend ActiveSupport::Concern

            included do
              after_validation :set_expiration_time, if: -> { respond_to?(:expirable_column) }
            end

            def set_expiration_time
              return if send(self.class.expirable_column).present?

              ttl = expirable_expires_in
              send("#{expirable_column}=", Time.now.utc + ttl)
            end

            def expired?(now=nil)
              return false unless send(expirable_column)

              now ||= Time.now.utc
              expires_at = send(expirable_column)

              if now > expires_at + expirable_grace_period
                expirable_on_expire
                true
              else
                touch_expiration! if expirable_touch_on_access
                false
              end
            end

            def touch_expiration!
              return unless expirable_auto_extend

              ttl = expirable_expires_in
              send("#{expirable_column}=", Time.now.utc + ttl)
              save! if respond_to?(:save!)
            end

          end

        end
      end
    end
  end
end
