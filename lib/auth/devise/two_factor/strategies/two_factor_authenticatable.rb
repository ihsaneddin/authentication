
  module Devise
      module Strategies
        class TwoFactorAuthenticatable < ::Devise::Strategies::DatabaseAuthenticatable

          def authenticate!
            resource = mapping.to.find_for_database_authentication(authentication_hash)
            if validate(resource) { validate_otp(resource) }
              super
            end

            fail(Devise.paranoid ? :invalid : :not_found_in_database) unless resource

            @halted = false if @result == :failure
          end

          def validate_otp(resource)
            return true unless resource.otp_required_for_login
            return if params[scope]['otp_attempt'].nil?
            resource.validate_and_consume_otp!(params[scope]['otp_attempt'])
          end
        end
      end
  end

Warden::Strategies.add(:two_factor_authenticatable, Devise::Strategies::TwoFactorAuthenticatable)
