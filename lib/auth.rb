require 'auth/devise'
require 'doorkeeper'
require 'jwt'

require 'auth/doorkeeper/jwt'
require 'auth/doorkeeper/jwt/config'
require 'auth/doorkeeper/request/otp'
require "auth/version"
require "auth/engine"

module Auth

  mattr_accessor :devise
  @@devise = ::Devise

  mattr_accessor :devise_default_modules
  @@devise_default_modules = [:database_authenticatable, :registerable,
  :recoverable, :rememberable, :validatable, :confirmable]

  mattr_accessor :devise_routes_enabled
  @@devise_routes_enabled = true

  mattr_accessor :resources
  @@resources = { accounts: {class_name: "Auth::Account", path: "accounts", module: :devise} }

  mattr_accessor :doorkeeper_enabled
  @@doorkeeper_enabled = true

  mattr_accessor :doorkeeper
  @@doorkeeper = ::Doorkeeper

  mattr_accessor :doorkeeper_route_name
  @@doorkeeper_route_name = :doorkeeper

  mattr_accessor :jwt
  @@jwt = Auth::Doorkeeper::JWT

  def self.devise_setup
    yield(@@devise)
  end

  def self.doorkeeper_setup &block
    if @@doorkeeper_enabled
      ::Doorkeeper.configure(&block)
    end
  end

  def self.enable_jwt
    @@doorkeeper.config.instance_variable_set("@access_token_generator", 'Auth::Doorkeeper::JWT')
    @@jwt = Auth::Doorkeeper::JWT
  end

  def self.jwt_setup
    if @@doorkeeper_enabled
      enable_jwt
      yield(@@jwt)
    end
  end

  def self.setup
    yield(self)
  end

end

# module Devise
#   mattr_accessor :otp_secret_length
#   @@otp_secret_length = 24

#   mattr_accessor :otp_allowed_drift
#   @@otp_allowed_drift = 60

#   mattr_accessor :otp_secret_encryption_key
#   @@otp_secret_encryption_key = nil

#   mattr_accessor :otp_backup_code_length
#   @@otp_backup_code_length = 5

#   mattr_accessor :otp_number_of_backup_codes
#   @@otp_number_of_backup_codes = 5
# end

# Devise.add_module(:two_factor_authenticatable, :route => :session, :strategy => true,
#                   :controller => :sessions, :model  => true)

# Devise.add_module(:two_factor_backupable, :route => :session, :strategy => true,
#                   :controller => :sessions, :model  => true)

require 'auth/hooks'