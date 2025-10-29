class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

  class << self
    #
    # @Override
    # override database authentication key
    #
    def find_for_database_authentication(warden_conditions)
      conditions = warden_conditions.dup
      login = conditions.delete(:login)
      if login.present?
        where(conditions.to_h).where([::Devise.authentication_keys.map{|d| "lower(#{d}) = :value" }.join(" or "), { :value => login.downcase }]).first
      elsif conditions.has_key?(:username) || conditions.has_key?(:email)
        where(conditions.to_h).first
      end
    end
  end

  authenticatable do
    doorkeeper do
      enabled true
      resource_owner_from_credentials do |request|
        keys = ::Devise.authentication_keys
        key = keys.find { |ak| !request.params[ak].blank? }
        user = find_for_database_authentication(:login => request.params[key])
        if user && user.valid_for_authentication? { user.valid_password?(request.params[:password]) }
          user
        end
      end
    end
  end
end
