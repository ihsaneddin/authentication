module Auth
  module Configuration
    module Doorkeeper
      module Extensions

        mattr_accessor :jwt
        @@jwt = ::Auth::Configuration::Doorkeeper::JWT

        def self.setup &block
          raise "Block is not provided" unless block_given?
          block.arity.zero? ? instance_eval(&block) : yield(self)
        end

        def self.enable_http_only_token *args, &block
          cookie_args = args.blank?? [
            "Path=/",
            'HttpOnly',
            'SameSite=strict'
          ] : args

          if block_given?
            cookie_args = yield(cookie_args)
          end

          ::Auth::Decorators::Doorkeeper::HttpOnlyTokenResponse.set_http_only_response_on_doorkeeper_token_response(*cookie_args)

          callback = lambda {|request|
            request.cookies['access_token']
          }
          @@doorkeeper.config.instance_variable_set(:@access_token_methods, callback)
        end
      end
    end
  end
end