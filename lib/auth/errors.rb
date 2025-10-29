module Auth
  module Errors

    module TwoFactorAuthentication

      class SessionMaxAttemptsReached < StandardError

      end

      class SessionAlreadyVerified < StandardError

      end

      class SessionExpired < StandardError

      end

    end

  end
end