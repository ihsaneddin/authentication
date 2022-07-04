module Auth
  module Doorkeeper
    module Request
      class OTP < ::Doorkeeper::Request::Strategy
        delegate :credentials, :resource_owner, :parameters, :client, to: :server

        attr_accessor :account

        def request
          @request ||= ::Doorkeeper::OAuth::PasswordAccessTokenRequest.new(
            ::Doorkeeper.config,
            client,
            account || resource_owner,
            parameters,
          )
        end
      end
    end
  end
end
