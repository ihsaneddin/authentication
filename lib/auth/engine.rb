module Auth
  class Engine < ::Rails::Engine
    isolate_namespace Auth

    initializer 'auth.routes' do
      Auth::Routes.install!
    end

    initializer 'auth.models_decorators' do
      ActiveSupport.on_load(:active_record) do
        include ::Auth::Models::Decorators::Authenticatable
      end
    end


  end
end
