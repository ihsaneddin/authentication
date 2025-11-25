module Auth
  module Errors

    class Unauthenticated  < StandardError
    end

    module TwoFactorAuthentication

      class SessionMaxAttemptsReached < StandardError
        def initialize(msg = "Maximum attempt is reached!")
          super(msg)
        end
      end

      class SessionAlreadyVerified < StandardError
        def initialize(msg = "Session is already verified!")
          super(msg)
        end
      end

      class SessionExpired < StandardError
        def initialize(msg = "Session is expired!")
          super(msg)
        end
      end

    end

  end
end