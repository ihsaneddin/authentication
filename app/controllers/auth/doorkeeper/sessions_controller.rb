module Auth::Doorkeeper
  class SessionsController < Doorkeeper::TokensController

    include ::Auth::Controllers::Concerns::DoorkeeperTokens

  end
end