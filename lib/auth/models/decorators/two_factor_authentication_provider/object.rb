module Auth
  module Models
    module Decorators
      module TwoFactorAuthenticationProvider
        module Object

          extend ActiveSupport::Concern

          included do
            belongs_to :authenticatable, polymorphic: true

            encrypts :secret

            has_many :sessions, class_name: "Auth::TwoFactorAuthenticationSession", foreign_key: "provider_id", dependent: :destroy

            validates :name, presence: true,
                             uniqueness: { scope: [:authenticatable_id, :authenticatable_type] },
                             inclusion: { in: :provider_names_list }

            delegate :config, to: :provider

            [:before_validation, :validate, :after_validation, :before_create, :after_create, :before_save, :after_save].each do |callback|
              send(callback) do
                if provider
                  config.object.callbacks.with_context(self) do
                    config.object.callbacks.send(callback)
                  end
                end
              end
            end

          end

          def provider_names_list
            ::Auth::Providers::TwoFactorAuthentication.registered_classes.map{|klass| klass.config_name }
          end

          def provider_class
            ::Auth::Providers::TwoFactorAuthentication.registered_classes.select{|klass| klass.config.name == name }
          end

          def provider
            @provider ||= provider_class.new(object: self) rescue nil
          end

        end
      end
    end
  end
end