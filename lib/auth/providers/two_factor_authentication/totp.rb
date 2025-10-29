module Auth
  module Providers
    module TwoFactorAuthentication
      class Totp

        include ::Auth::Providers::TwoFactorAuthentication

        add_config :secret_generator, proc { ROTP::Base32.random_base32(24) }
        add_config :digits, 4
        add_config :interval, 30
        add_config :allowed_drift, 60
        add_config :secret, proc { object.secret }
        add_config :last_verified_at, proc { object.sessions.where.not(verified_at: nil).order("updated_at desc").first.try(:verified_at) }

        configure do
          object do
            callbacks do
              before_save do
                self.secret ||= provider.generate_secret
              end
            end
          end
        end

        initiation do
          totp.now
        end

        verification do |session, code|
          totp.verify(code, drift_ahead: config.allowed_drift, drift_behind: config.allowed_drift, after: config.last_verified_at)
        end

        def totp(secret = object.secret, options ={digits: config.digits, interval: config.interval})
          @totp ||= ROTP::TOTP.new(secret, options)
        end

        def generate_secret
          config.secret_generator
        end

      end
    end
  end
end