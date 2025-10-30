module Auth
  module Errors

    class Unauthenticated  < StandardError
    end

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