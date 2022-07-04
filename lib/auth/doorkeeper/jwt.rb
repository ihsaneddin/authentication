module Auth::Doorkeeper
  module JWT
    class << self
      def generate(opts = {})
        ::JWT.encode(
          token_payload(opts),
          secret_key(opts),
          encryption_method,
          token_headers(opts)
        )
      end

      private

      def token_payload(opts = {})
        Auth::Doorkeeper::JWT.configuration.token_payload.call(opts)
      end

      def token_headers(opts = {})
        Auth::Doorkeeper::JWT.configuration.token_headers.call(opts)
      end

      def secret_key(opts)
        opts = { application: {} }.merge(opts)

        return application_secret(opts) if use_application_secret?
        return secret_key_file unless secret_key_file.nil?
        return rsa_key if rsa_encryption?
        return ecdsa_key if ecdsa_encryption?

        Auth::Doorkeeper::JWT.configuration.secret_key
      end

      def secret_key_file
        return nil if Auth::Doorkeeper::JWT.configuration.secret_key_path.nil?
        return rsa_key_file if rsa_encryption?
        return ecdsa_key_file if ecdsa_encryption?
      end

      def encryption_method
        return "none" unless Auth::Doorkeeper::JWT.configuration.encryption_method

        Auth::Doorkeeper::JWT.configuration.encryption_method.to_s.upcase
      end

      def use_application_secret?
        Auth::Doorkeeper::JWT.configuration.use_application_secret
      end

      def application_secret(opts)
        if opts[:application].nil?
          raise(
            "JWT `use_application_secret` is enabled, but application is nil." \
            " This can happen if `client_id` was absent in the request params."
          )
        end

        secret = if opts[:application].respond_to?(:plaintext_secret)
                   unless opts[:application].secret_strategy.allows_restoring_secrets?
                     raise(
                       "JWT `use_application_secret` is enabled, but secret strategy " \
                       "doesn't allow plaintext secret restoring"
                     )
                   end
                   opts[:application].plaintext_secret
                 else
                   opts[:application][:secret]
                 end

        if secret.nil?
          raise(
            "JWT `use_application_secret` is enabled, but the application" \
            " secret is nil."
          )
        end

        secret
      end

      def rsa_encryption?
        /RS\d{3}/ =~ encryption_method
      end

      def ecdsa_encryption?
        /ES\d{3}/ =~ encryption_method
      end

      def rsa_key
        OpenSSL::PKey::RSA.new(Auth::Doorkeeper::JWT.configuration.secret_key)
      end

      def ecdsa_key
        OpenSSL::PKey::EC.new(Auth::Doorkeeper::JWT.configuration.secret_key)
      end

      def rsa_key_file
        secret_key_file_open { |f| OpenSSL::PKey::RSA.new(f) }
      end

      def ecdsa_key_file
        secret_key_file_open { |f| OpenSSL::PKey::EC.new(f) }
      end

      def secret_key_file_open(&block)
        File.open(Auth::Doorkeeper::JWT.configuration.secret_key_path, &block)
      end
    end
  end
end
