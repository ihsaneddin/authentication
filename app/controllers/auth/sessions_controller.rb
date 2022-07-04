module Auth
  class SessionsController < Devise::SessionsController

    include Auth::Concerns::DeviseTwoFactorAuthentication

    prepend_before_action :authenticate_with_otp_two_factor,
                        if: -> { action_name == 'create' && otp_two_factor_enabled? }

  end
end
