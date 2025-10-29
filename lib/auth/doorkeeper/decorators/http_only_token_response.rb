module Auth
  module Doorkeeper
    module Decorators
      module HttpOnlyTokenResponse

        mattr_accessor :cookie_args
        @@cookie_args = []

        def self.set_http_only_response_on_doorkeeper_token_response(*args)
          self.cookie_args = args
          Rails.application.config.to_prepare do
            ::Doorkeeper::OAuth::TokenResponse.send :prepend, ::Auth::Decorators::Doorkeeper::HttpOnlyTokenResponse::InstanceMethods
          end
        end

        module InstanceMethods
          def body
            res = super.except('access_token', 'token_id', 'refresh_token', 'token_type')
            res['token_type'] = 'httponly'
            res
          end

          def headers
            args = ::Auth::Doorkeeper::Decorators::HttpOnlyResponse.cookie_args
            args.push "access_token=#{token.token}"
            args = args.join("; ")
            super.merge({'Set-Cookie' => args})
          end
        end

      end
    end
  end
end