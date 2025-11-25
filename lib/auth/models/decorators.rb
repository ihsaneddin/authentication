module Auth
  module Models
    module Decorators

      autoload :Authenticatable, "auth/models/decorators/authenticatable"
      autoload :TwoFactorAuthenticationProvider, "auth/models/decorators/two_factor_authentication_provider"
      autoload :TwoFactorAuthenticationSession, "auth/models/decorators/two_factor_authentication_session"
      autoload :Code, "auth/models/decorators/code"

    end
  end
end