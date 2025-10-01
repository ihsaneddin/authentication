module Auth
  module Doorkeeper
    module Response
      module HttponlyToken
        
        def body 
          res = super.except('access_token', 'token_id', 'refresh_token', 'token_type')
          res['token_type'] = 'httponly'
          res
        end

        def headers
          args = Auth.cookie_args
          args.push "access_token=#{token.token}"
          args = args.join("; ")
          super.merge({'Set-Cookie' => args})
        end
      
      end
    end
  end
end