module Auth
  module Routes

    def self.install!
      ActionDispatch::Routing::Mapper.include(Helpers)
    end

    module Helpers
      def use_doorkeeper_token_authenticatable_routes(base_scope: "auth", path: "sessions", controller: "/auth/doorkeeper/sessions")
        each_enabled_authenticatable do |klass, route_segment|
          use_doorkeeper_token_authenticatable_route(
            klass,
            segment: route_segment,
            base_scope: base_scope,
            path: path,
            controller: controller
          )
        end
      end

      def use_doorkeeper_token_authenticatable_route(klass, segment: nil, base_scope: "auth", path: 'sessions', controller: "/auth/doorkeeper/sessions")
        raise ArgumentError, "klass must respond to .auth_config" unless klass.respond_to?(:auth_config)
        cfg = klass.auth_config
        return unless cfg.doorkeeper.enabled
        route_segment = segment

        defaults = {authenticatable: klass.name}

        scope base_scope do
          scope route_segment, defaults: defaults.merge({grant_type: "password" }) do
            post [path, ""].compact.join("/"),  to: "#{controller}#create",  as: :"#{route_segment}_token"
          end
          scope route_segment, defaults: defaults.merge({grant_type: "refresh_token" }) do
            post [path, "refresh"].compact.join("/"),  to: "#{controller}#create",  as: :"#{route_segment}_refresh_token"
          end
          scope route_segment, defaults: defaults do
            post [path, "revoke"].compact.join("/"), to: "#{controller}#revoke", as: :"#{route_segment}_revoke"
            post [path, "introspect"].compact.join("/"), to: "#{controller}#introspect", as: :"#{route_segment}_introspect"
          end
        end
      end

      private

      def each_enabled_authenticatable
        registered = ::Auth::Models::Decorators::Authenticatable.registered_classes
        registered.each do |klass_name|
          klass = klass_name.to_s.safe_constantize
          cfg = klass.auth_config
          next unless cfg.doorkeeper.enabled

          route_segment = cfg.name

          yield klass, route_segment
        end
      end
    end

  end
end
