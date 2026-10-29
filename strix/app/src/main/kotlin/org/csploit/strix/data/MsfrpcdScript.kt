package org.csploit.strix.data

/**
 * msfrpcd compatibility wrapper for MSF 6.x (the upstream script expects a
 * daemonizing environment). Written into the staged msf/ dir on every install.
 */
internal object MsfrpcdScript {
    val CONTENT: String =
        """
        |#!/usr/bin/env ruby
        |# msfrpcd - MSF RPC Daemon (compatibility wrapper for MSF 6.x)
        |
        |msfbase = __FILE__
        |while File.symlink?(msfbase)
        |  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
        |end
        |
        |${'$'}:.unshift(File.expand_path(File.join(File.dirname(msfbase), 'lib')))
        |require 'msfenv'
        |
        |opts = {
        |  'ServerHost' => '0.0.0.0',
        |  'ServerPort' => 55553,
        |  'User' => 'msf',
        |  'Pass' => 'msf',
        |  'SSL' => true,
        |}
        |
        |i = 0
        |while i < ARGV.length
        |  case ARGV[i]
        |  when '-a' then i += 1; opts['ServerHost'] = ARGV[i]
        |  when '-p' then i += 1; opts['ServerPort'] = ARGV[i].to_i
        |  when '-U' then i += 1; opts['User'] = ARGV[i]
        |  when '-P' then i += 1; opts['Pass'] = ARGV[i]
        |  when '-S' then opts['SSL'] = false
        |  end
        |  i += 1
        |end
        |
        |${'$'}0 = 'msfrpcd'
        |${'$'}stderr.puts "[*] MSGRPC starting on #{opts['ServerPort']} (#{opts['SSL'] ? 'SSL' : 'NO SSL'})..."
        |${'$'}stderr.flush
        |
        |framework = Msf::Simple::Framework.create
        |framework.plugins.load('msgrpc', opts)
        |
        |${'$'}stderr.puts "[*] MSGRPC ready at #{opts['ServerHost']}:#{opts['ServerPort']}"
        |${'$'}stderr.flush
        |
        |begin
        |  while true
        |    sleep 60
        |  end
        |rescue Interrupt, SignalException
        |  ${'$'}stderr.puts "[*] Shutting down msfrpcd..."
        |end
        """.trimMargin()
}
