# frozen_string_literal: true

# This logger writes to a separate file, isolating security events.
security_log_path = Rails.root.join('log', 'security.log')
# Use a file size rotator (10 files of 1MB each) to prevent the log from growing indefinitely.
SECURITY_LOGGER = ActiveSupport::Logger.new(security_log_path, 10, 1024 * 1024)

SECURITY_LOGGER.formatter = proc do |severity, datetime, _progname, msg|
  "[#{datetime.strftime('%Y-%m-%d %H:%M:%S')}] #{severity}: #{msg}\n"
end

ActiveSupport::Notifications.subscribe('warden.authentication.failure') do |_name, _start, _finish, _id, payload|
  env = payload[:env]
  request = ActionDispatch::Request.new(env)
  user_email = request.params.dig(:user, :email)

  log_message = {
    event: 'failed_login_attempt',
    email: user_email,
    ip_address: request.remote_ip,
    user_agent: request.user_agent,
    path: request.path
  }.to_json

  SECURITY_LOGGER.warn(log_message)
end