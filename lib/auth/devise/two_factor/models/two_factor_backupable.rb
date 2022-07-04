
  module Devise

      module Models
        module TwoFactorBackupable
          extend ActiveSupport::Concern

          def self.required_fields(klass)
            [:otp_backup_codes]
          end

          def generate_otp_backup_codes!
            codes           = []
            number_of_codes = self.class.otp_number_of_backup_codes
            code_length     = self.class.otp_backup_code_length

            number_of_codes.times do
              codes << SecureRandom.hex(code_length / 2) # Hexstring has length 2*n
            end

            hashed_codes = codes.map { |code| Devise::Encryptor.digest(self.class, code) }
            self.otp_backup_codes = hashed_codes

            codes
          end

          def invalidate_otp_backup_code!(code)
            codes = self.otp_backup_codes || []

            codes.each do |backup_code|
              next unless Devise::Encryptor.compare(self.class, backup_code, code)

              codes.delete(backup_code)
              self.otp_backup_codes = codes
              return true
            end

            false
          end

        protected

          module ClassMethods
            ::Devise::Models.config(self, :otp_backup_code_length,
                                        :otp_number_of_backup_codes)
          end
        end
      end

  end
