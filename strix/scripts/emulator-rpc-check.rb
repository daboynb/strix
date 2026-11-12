# Device side of emulator-msf-test.sh: the app's first RPC calls against a running
# msfrpcd (MsfRpcHttp.kt: msgpack POST to /api/ over self-signed TLS).
#
#   ruby emulator-rpc-check.rb <port> <password>
# Exit 0 only if auth.login, core.version and core.module_stats succeed.

require 'net/http'
require 'openssl'
require 'msgpack'

port = Integer(ARGV.fetch(0))
pass = ARGV.fetch(1)

rpc = lambda do |*call|
  http = Net::HTTP.new('127.0.0.1', port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  http.open_timeout = http.read_timeout = 120
  res = http.post('/api/', call.to_msgpack, 'Content-Type' => 'binary/message-pack')
  raise "#{call.first}: HTTP #{res.code}" unless res.code == '200'

  MessagePack.unpack(res.body)
end

login = rpc.call('auth.login', 'msf', pass)
raise "auth.login failed: #{login.inspect}" unless login['result'] == 'success' && login['token']

token = login['token']
version = rpc.call('core.version', token)
raise "core.version failed: #{version.inspect}" unless version['version']

stats = rpc.call('core.module_stats', token)
raise "core.module_stats failed: #{stats.inspect}" unless stats['exploits'].to_i.positive?

puts "PASS: msfrpcd RPC on Android: Metasploit #{version['version']}, ruby #{version['ruby']}, " \
     "#{stats['exploits']} exploits, #{stats['payloads']} payloads"
