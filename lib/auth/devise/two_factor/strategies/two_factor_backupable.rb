
  module Devise

      module Strategies
        class TwoFactorBackupable < ::Devise::Strategies::DatabaseAuthenticatable

          def authenticate!
            resource = mapping.to.find_for_database_authentication(authentication_hash)

            if validate(resource) { resource.invalidate_otp_backup_code!(params[scope]['otp_attempt']) }
              resource.save!
              super
            end

            fail(Devise.paranoid ? :invalid : :not_found_in_database) unless resource

            @halted = false if @result == :failure
          end
        end
      end

  end

Warden::Strategies.add(:two_factor_backupable, Devise::Strategies::TwoFactorBackupable)
