# Load test of the bundled Metasploit, run by build-msf.sh with the host Ruby (built
# like the Android one: static, exported stdlib extensions) before anything ships.
# Same steps as the app's msfrpcd wrapper (MsfrpcdScript.kt): msfenv, framework,
# msgrpc plugin over SSL; then the app's first RPC calls: auth.login, core.version.
#
#   ruby msf-load-test.rb <metasploit-framework dir>
# Exit 0 only if every step works; any exception fails the build (issue #13).

require 'securerandom'

msf_dir = File.expand_path(ARGV.fetch(0))
$:.unshift(File.join(msf_dir, 'lib'))

started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
step = ->(msg) { $stderr.puts format('[load-test %5.1fs] %s', Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, msg) }

step.call('require msfenv')
require 'msfenv'

step.call('Msf::Simple::Framework.create')
framework = Msf::Simple::Framework.create
step.call("modules: #{framework.stats.num_exploits} exploits, #{framework.stats.num_payloads} payloads")
raise 'no exploit modules loaded' if framework.stats.num_exploits.zero?

require 'net/http'
require 'openssl'
require 'msgpack'

pass = SecureRandom.hex(12)
server = TCPServer.new('127.0.0.1', 0)
port = server.addr[1]
server.close

step.call("load msgrpc plugin on 127.0.0.1:#{port} (SSL)")
plugin = framework.plugins.load('msgrpc', 'ServerHost' => '127.0.0.1', 'ServerPort' => port,
                                          'User' => 'msf', 'Pass' => pass, 'SSL' => true)
raise 'msgrpc plugin did not load' unless plugin

# The plugin starts its server in a worker thread (msgrpc.rb: Thread.new { run }),
# as on the device, where the app also waits for the port: wait up to 60 s.
deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 60
begin
  TCPSocket.new('127.0.0.1', port).close
rescue Errno::ECONNREFUSED
  raise 'msgrpc server not listening after 60 s' if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

  sleep 0.5
  retry
end
step.call('msgrpc listening')

rpc = lambda do |*call|
  http = Net::HTTP.new('127.0.0.1', port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  http.open_timeout = http.read_timeout = 60
  res = http.post('/api/', call.to_msgpack, 'Content-Type' => 'binary/message-pack')
  raise "#{call.first}: HTTP #{res.code}" unless res.code == '200'

  MessagePack.unpack(res.body)
end

login = rpc.call('auth.login', 'msf', pass)
raise "auth.login failed: #{login.inspect}" unless login['result'] == 'success' && login['token']

version = rpc.call('core.version', login['token'])
raise "core.version failed: #{version.inspect}" unless version['version']

step.call("PASS: RPC core.version #{version['version']}, ruby #{version['ruby']}")
$stderr.flush
# The framework keeps non-daemon threads (RPC server, module cache): don't wait for them.
exit!(0)
