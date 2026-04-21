package org.csploit.strix.data

/**
 * Maps nmap service names to hydra module names.
 * Determines which attack modules are available for a given service.
 * Returned list is ordered by preference (most likely to work first).
 */
object HydraModules {

    data class AttackOption(
        val module: String,
        val defaultPath: String = "/",
    )

    fun forService(service: String?, port: Int): List<AttackOption> {
        val svc = service?.lowercase()?.trim() ?: return guessFromPort(port)

        return when {
            svc.contains("ssl/http") || svc.contains("https") -> listOf(
                AttackOption("https-get"),
                AttackOption("https-post-form"),
            )
            svc.contains("http") -> listOf(
                AttackOption("http-get"),
                AttackOption("http-post-form"),
            )
            svc.contains("ssh") -> listOf(AttackOption("ssh"))
            svc.contains("ftp") -> listOf(AttackOption("ftp"))
            svc.contains("telnet") -> listOf(AttackOption("telnet"))
            svc.contains("smtp") -> listOf(AttackOption("smtp"))
            svc.contains("pop3") -> listOf(AttackOption("pop3"))
            svc.contains("imap") -> listOf(AttackOption("imap"))
            svc.contains("vnc") -> listOf(AttackOption("vnc"))
            svc.contains("mysql") || svc.contains("mariadb") -> listOf(AttackOption("mysql"))
            svc.contains("ms-sql") || svc.contains("mssql") -> listOf(AttackOption("mssql"))
            svc.contains("postgresql") || svc.contains("postgres") -> listOf(AttackOption("postgres"))
            svc.contains("mongodb") || svc.contains("mongod") -> listOf(AttackOption("mongodb"))
            svc.contains("rdp") || svc.contains("ms-wbt-server") -> listOf(AttackOption("rdp"))
            svc.contains("snmp") -> listOf(AttackOption("snmp"))
            svc.contains("sip") -> listOf(AttackOption("sip"))
            svc.contains("ldap") -> listOf(AttackOption("ldap2"))
            svc.contains("smb") || svc.contains("microsoft-ds") || svc.contains("netbios") ->
                listOf(AttackOption("smb"))
            svc.contains("rtsp") -> listOf(AttackOption("rtsp"))
            svc.contains("irc") -> listOf(AttackOption("irc"))
            svc.contains("redis") -> listOf(AttackOption("redis"))
            svc.contains("memcache") -> listOf(AttackOption("memcached"))
            svc.contains("oracle") -> listOf(AttackOption("oracle-listener"))
            svc.contains("svn") || svc.contains("subversion") -> listOf(AttackOption("svn"))
            svc.contains("cisco") -> listOf(AttackOption("cisco"))
            svc.contains("nntp") -> listOf(AttackOption("nntp"))
            svc.contains("rexec") -> listOf(AttackOption("rexec"))
            svc.contains("rlogin") -> listOf(AttackOption("rlogin"))
            svc.contains("rsh") -> listOf(AttackOption("rsh"))
            svc.contains("xmpp") || svc.contains("jabber") -> listOf(AttackOption("xmpp"))
            svc.contains("teamspeak") -> listOf(AttackOption("teamspeak"))
            svc.contains("socks") -> listOf(AttackOption("socks5"))
            svc.contains("asterisk") -> listOf(AttackOption("asterisk"))
            svc.contains("cvs") || svc.contains("pserver") -> listOf(AttackOption("cvs"))
            svc.contains("radmin") -> listOf(AttackOption("radmin2"))
            svc.contains("pcnfs") -> listOf(AttackOption("pcnfs"))
            svc.contains("pcanywhere") -> listOf(AttackOption("pcanywhere"))
            svc.contains("vmauthd") -> listOf(AttackOption("vmauthd"))
            svc.contains("s7-") || svc.contains("siemens") -> listOf(AttackOption("s7-300"))
            svc.contains("cobaltstrike") -> listOf(AttackOption("cobaltstrike"))
            else -> guessFromPort(port)
        }
    }

    private fun guessFromPort(port: Int): List<AttackOption> = when (port) {
        22 -> listOf(AttackOption("ssh"))
        21 -> listOf(AttackOption("ftp"))
        23 -> listOf(AttackOption("telnet"))
        25, 587 -> listOf(AttackOption("smtp"))
        80, 8080, 8888 -> listOf(
            AttackOption("http-get"),
            AttackOption("http-post-form"),
        )
        110 -> listOf(AttackOption("pop3"))
        143 -> listOf(AttackOption("imap"))
        443, 8443 -> listOf(
            AttackOption("https-get"),
            AttackOption("https-post-form"),
        )
        445 -> listOf(AttackOption("smb"))
        512 -> listOf(AttackOption("rexec"))
        513 -> listOf(AttackOption("rlogin"))
        514 -> listOf(AttackOption("rsh"))
        993 -> listOf(AttackOption("imaps"))
        995 -> listOf(AttackOption("pop3s"))
        1433 -> listOf(AttackOption("mssql"))
        1521 -> listOf(AttackOption("oracle-listener"))
        2049 -> listOf(AttackOption("pcnfs"))
        3306 -> listOf(AttackOption("mysql"))
        3389 -> listOf(AttackOption("rdp"))
        3690 -> listOf(AttackOption("svn"))
        5060 -> listOf(AttackOption("sip"))
        5222 -> listOf(AttackOption("xmpp"))
        5432 -> listOf(AttackOption("postgres"))
        5900, 5901 -> listOf(AttackOption("vnc"))
        6379 -> listOf(AttackOption("redis"))
        11211 -> listOf(AttackOption("memcached"))
        27017 -> listOf(AttackOption("mongodb"))
        50000 -> listOf(AttackOption("s7-300"))
        else -> emptyList()
    }
}
