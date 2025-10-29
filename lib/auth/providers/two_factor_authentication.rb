module Auth
  module Providers
    module TwoFactorAuthentication

      extend Plugins::Decorators::ConfigBuilder

      mattr_accessor :registered_classes
      @@registered_classes = Set.new

      def self.register(klass)
        @@registered_classes << klass
      end

      def self.included base

        base.include ::Plugins.decorators.method_annotations
        base.include ::Plugins.decorators.smart_send
        base.include ::Plugins.decorators.method_decorators
        base.include ::Plugins.decorators.inheritables.singleton_methods
        base.include ::Plugins::Models::Concerns::Eventable::PublishesEvents

        base.inheritable_class_attribute :provider_name
        base.provider_name = base.name.demodulize.underscore

        functions = [
          :initiation, :verification
        ]

        functions.each do |funct|
          base.define_inheritable_singleton_method funct do |method_name = nil, &block|
            method_name ||= :"#{funct}_#{SecureRandom.hex(8)}"
            annotate_method(method_name, funct.to_sym => true, &block)
          end

          [:before, :after].each do |callback|
            base.define_inheritable_singleton_method "#{callback}_#{funct}" do |method_name = nil, &block|
              method_name ||= :"#{callback}_#{funct}_#{SecureRandom.hex(8)}"
              annotate_method(method_name, "#{callback}_#{funct}".to_sym => true, &block)
            end
          end
        end

        config_class.setup(base,
          'config',
          {},
          default_options,
          method_prefix: "config",
          &block
        )

        base.include InstanceMethods

        base.before_initiation :before_initiation
        base.after_initiation :after_initiation
        base.before_verification :before_verification
        base.after_verification :after_verification

        register(base)

      end

      def self.default_options
         defaults = {
          name: proc {
            self.is_a?(Class) ? provider_name : self.class.provider_name
          },
          initiation: :initiate_two_factor_authentication,
          verification: :verify_two_factor_authentication,
          verification_logical_operator: "and",
          object: config_builder(**{
            callbacks: config_builder(**{
              before_validation: nil,
              validate: nil,
              afeter_validation: nil,
              before_create: nil,
              before_save: nil,
              after_create: nil,
              after_save: nil
            })
          }),
          session: config_builder(**{
            expires_in: 5.minutes,
            uid: proc {
              "#{SecureRandom.hex(8)}"
            },
            max_attempts: 3,
            create: proc {
              object.sessions.create({
                session_uid: config_session.uid,
                expires_at: Time.now + config_session.expires_in
              })
            },
          }),
        }
        defaults
      end

      module ClassMethods

        def configure **opts, &block
          config.setup(**opts, &block)
        end

        def add_configuration key, default_value=nil
          config.add(key.to_sym, default_value)
        end

      end

      module InstanceMethods
        extend ActiveSupport::Concern

        included do
          attr_reader :object, :authenticatable
        end

        def initialize(object: )
          @object = object
          @authenticatable = object.authenticatable
        end

        def initiate_two_factor_authentication(*args)
          perform_before_initiation(*args)
          session = perform_initiation(*args)
          if session.persisted?
            after_initiation(session, *args)
          end
          session
        end

        def verify_two_factor_authentication(session, authentication, *args)
          session.current_authentication = authentication
          perform_before_verification(session, authentication, *args)
        end

        protected

        def before_initiation(*args)
          payload = {authenticatable: authenticatable, object: self}
          publish_event('before_initiation', bus: :two_factor_authentication, **payload)
        end

        def perform_before_initiation(*args)
          self.class.methods_annotated_with(:before_initiation, true).each{|mname| smart_send(*args) }
        end

        def perform_initiation(*args)
          initiation_methods = self.class.methods_annotated_with(:initiation, true)

          raise "Multiple initiation methods are not allowed" if initiation_methods.length > 1

          session = config_session.create
          mname = initiation_methods[0]
          session.current_authentication = smart_send(mname, *args) if mname
          session
        end

        def perform_after_initiation(session, *args)
          arguments = args.unshift(session)
          self.class.methods_annotated_with(:after_initiation, true).each{|mname| smart_send(*arguments) }
        end

        def after_initiation(session, *args)
          payload = opts.merge(authenticatable: authenticatable, object: self, session: session, current_authentication: session.current_authentication)
          publish_event('after_initiation', bus: :two_factor_authentication, **payload)
        end

        def before_verification(session, authentication, *args)
          payload = opts.merge(authenticatable: authenticatable, object: self)
          publish_event('before_verification', bus: :two_factor_authentication, **payload)
        end

        def perform_before_verification(session, authentication, *args)
          arguments = args.unshift(session)
          arguments = args.unshift(authentication)
          self.class.methods_annotated_with(:before_verification, true).each{|mname| smart_send(*arguments) }
        end

        def perform_verification(session, authentication,  *args)
          perform_before_verification(session, authentication, *args)
          verification_methods = self.class.methods_annotated_with(:verification, true)
          authenticated = session.attempt!(config.session.max_attempts) do
            arguments = args.unshift(session)
            arguments = args.unshift(authentication)
            verification_methods.map{|mname| smart_send(mname, *arguments) }.reduce{|result, step| config.verification_logical_operator == "and" ? result && step : result || step }
          end
          if authenticated
            peform_after_verification(session, authentication, *args)
          end
          authenticated
        end

        def perform_after_verification session, **opts
          arguments = args.unshift(session)
          arguments = args.unshift(authentication)
          self.class.methods_annotated_with(:after_verification, true).each{|mname| smart_send(*arguments) }
        end

        def after_verification(session, **opts)
          payload = opts.merge(authenticatable: authenticatable, object: self)
          publish_event('after_verification', bus: :two_factor_authentication, **payload)
        end
      end

      autoload :Totp, "auth/providers/two_factor_authentication/totp"

    end
  end
end