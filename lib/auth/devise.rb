require 'devise'
require 'auth/devise/two_factor/models'
require 'auth/devise/two_factor/strategies'

module Devise
  mattr_accessor :otp_secret_length
  @@otp_secret_length = 24

  mattr_accessor :otp_allowed_drift
  @@otp_allowed_drift = 60

  mattr_accessor :otp_digits_length
  @@otp_digits_length = 6

  mattr_accessor :otp_interval
  @@otp_interval = 30

  mattr_accessor :otp_secret_encryption_key
  @@otp_secret_encryption_key = nil

  mattr_accessor :otp_backup_code_length
  @@otp_backup_code_length = 5

  mattr_accessor :otp_number_of_backup_codes
  @@otp_number_of_backup_codes = 5
end

Devise.add_module(:two_factor_authenticatable, :route => :session, :strategy => true,
                  :controller => :sessions, :model  => true)

Devise.add_module(:two_factor_backupable, :route => :session, :strategy => true,
                  :controller => :sessions, :model  => true)
