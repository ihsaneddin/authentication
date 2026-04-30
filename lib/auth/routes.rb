module Auth
  module Routes

    def self.install!
      ActionDispatch::Routing::Mapper.include(Helpers)
    end

    module Helpers
      def use_doorkeeper_token_authenticatable_routes(base_scope: "auth", path: "sessions", controller: "/auth/doorkeeper/sessions", use_default_scope: true, scope: nil)
        each_enabled_authenticatable do |klass, route_segment|
          use_doorkeeper_token_authenticatable_route(
            klass,
            segment: route_segment,
            base_scope: base_scope,
            path: path,
            controller: controller,
            use_default_scope: use_default_scope,
            scope: scope
          )
        end
      end

      def use_doorkeeper_token_authenticatable_route(klass, segment: nil, base_scope: "auth", path: 'sessions', controller: "/auth/doorkeeper/sessions", use_default_scope: true, scope: nil)
        raise ArgumentError, "klass must respond to .auth_config" unless klass.respond_to?(:auth_config)
        cfg = klass.auth_config
        return unless cfg.doorkeeper.enabled
        route_segment = segment

        defaults = { authenticatable: klass.name }
        defaults[:scope] = scope unless scope.nil?
        defaults[:scope] = klass.auth_doorkeeper.default_scope if scope.nil? && use_default_scope
        scope base_scope do
          scope route_segment, defaults: defaults.merge({grant_type: klass.auth_doorkeeper.default_grant_type }) do
            post [path, ""].compact.join("/"),  to: "#{controller}#create",  as: :"#{route_segment}#{klass.auth_name}_token"
          end
          if klass.auth_doorkeeper.grant_types.include?("refresh_token")
            scope route_segment, defaults: defaults.merge({grant_type: "refresh_token" }) do
              post [path, "refresh"].compact.join("/"),  to: "#{controller}#create",  as: :"#{route_segment}#{klass.auth_name}_refresh_token"
            end
          end
          scope route_segment, defaults: defaults do
            post [path, "revoke"].compact.join("/"), to: "#{controller}#revoke", as: :"#{route_segment}#{klass.auth_name}_revoke"
            post [path, "introspect"].compact.join("/"), to: "#{controller}#introspect", as: :"#{route_segment}#{klass.auth_name}_introspect"
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
