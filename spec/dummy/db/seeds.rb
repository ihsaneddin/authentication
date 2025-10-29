[
  Auth::TwoFactorAuthenticationSession, Auth::Identity, User,
  Auth::TwoFactorAuthenticationProvider, Auth::Application, Auth::AccessToken, Auth::AccessGrant
].each do |mod|
  begin
    mod.delete_all
  rescue => e
    debugger
    raise e
  end
end

User.create!(
  username: "aing",
  email: "aing@mail.com",
  password: "password",
  password_confirmation: "password"
)