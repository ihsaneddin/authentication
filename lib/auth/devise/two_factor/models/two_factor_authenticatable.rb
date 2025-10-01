require 'rotp'


  module Devise

      module Models
        module TwoFactorAuthenticatable
          extend ActiveSupport::Concern
          include ::Devise::Models::DatabaseAuthenticatable

          included do
            unless %i[otp_secret otp_secret=].all? { |attr| method_defined?(attr) }
              encrypts :otp_secret
            end

            attr_accessor :otp_attempt
          end

          def self.required_fields(klass)
            [:otp_secret, :consumed_timestep]
          end

          def validate_and_consume_otp!(code, options = {})
            otp_secret = options[:otp_secret] || self.otp_secret
            return false unless code.present? && otp_secret.present?

            totp = otp(otp_secret)
            if totp.verify(code, drift_ahead: self.class.otp_allowed_drift, drift_behind: self.class.otp_allowed_drift)
              return consume_otp!
            end

            false
          end

          def otp(otp_secret = self.otp_secret, options ={digits: self.class.otp_digits_length, interval: self.class.otp_interval})
            ROTP::TOTP.new(otp_secret, options)
          end

          def current_otp
            otp.at(Time.now)
          end

          def current_otp_timestep
             Time.now.utc.to_i / otp.interval
          end

          def otp_provisioning_uri(account, options = {})
            otp_secret = options[:otp_secret] || self.otp_secret
            ROTP::TOTP.new(otp_secret, options).provisioning_uri(account)
          end

          def clean_up_passwords
            super
            self.otp_attempt = nil
          end

        protected

          def consume_otp!
            if self.otp_consumed_timestep != current_otp_timestep
              self.otp_consumed_timestep = current_otp_timestep
              return save(validate: false)
            end

            false
          end

          module ClassMethods
            ::Devise::Models.config(self, :otp_secret_length,
                                        :otp_digits_length,
                                        :otp_interval,
                                        :otp_allowed_drift,
                                        :otp_secret_encryption_key)

            def generate_otp_secret(otp_secret_length = self.otp_secret_length)
              ROTP::Base32.random_base32(otp_secret_length)
            end
          end
        end
      end

  end
