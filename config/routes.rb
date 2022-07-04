Auth::Engine.routes.draw do
  if Auth.doorkeeper_enabled
    namespace :doorkeeper do
      resources :sessions, only: [:create, :destroy], param: :token, controller: "sessions"
      resource :sessions, only: [:destroy], controller: "sessions"
    end
  end

  if Auth.devise_routes_enabled
    Auth.resources.each do |k,v|
      devise_for k,v
    end
  end

end
