package org.csploit.strix.data

/**
 * Shell command builders for [MitmRunner]: setup, cleanup, restore and kill
 * rules. Setup and cleanup are built side by side for symmetry.
 */
internal object MitmCommands {
    const val TETHER_FORWARD = "tetherctrl_FORWARD"

    /** Insert [rule] (an `iptables` rule body beginning with the table/chain) only if absent. */
    fun insertIfAbsent(rule: String): String =
        "iptables -C ${rule} 2>/dev/null || iptables -I ${rule}"

    fun setupCommands(iface: String, gateway: String, mode: MitmMode): List<String> {
        val cmds = mutableListOf(
            "ndc ipfwd enable strix",
            "echo 1 > /proc/sys/net/ipv4/ip_forward",
            "iptables -F $TETHER_FORWARD",               // remove DROP-all (surgical, not -F)
            "iptables -P FORWARD ACCEPT",
            insertIfAbsent("-t nat POSTROUTING -s 0/0 -j MASQUERADE"),
            "ip route add default via $gateway dev $iface 2>/dev/null; true",
            "echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects; echo 0 > /proc/sys/net/ipv4/conf/$iface/send_redirects",
            // ip rule has no -C; the explicit del-before-add keeps it single.
            "ip rule del iif $iface lookup $iface pref 31500 2>/dev/null; " +
                "ip rule add iif $iface lookup $iface pref 31500 2>/dev/null; true",
        )
        if (mode == MitmMode.DNS_SPOOF) {
            cmds.add(insertIfAbsent(dnsRedirectRule(iface)))
        }
        return cmds
    }

    fun cleanupCommands(iface: String, mode: MitmMode): List<String> {
        val cmds = mutableListOf(
            "ndc ipfwd disable strix",
            "ip rule del iif $iface lookup $iface pref 31500 2>/dev/null; true",
            // delete-until-absent: a prior unbalanced run may have left >1 copy.
            deleteAll("-t nat POSTROUTING -s 0/0 -j MASQUERADE"),
        )
        if (mode == MitmMode.DNS_SPOOF) {
            cmds.add(deleteAll(dnsRedirectRule(iface)))
        }
        return cmds
    }

    fun restoreCommands(snap: NetSnapshot?, iface: String): List<String> {
        val cmds = mutableListOf<String>()
        snap?.forwardPolicy?.let { cmds.add("iptables -P FORWARD $it") }
        snap?.sendRedirectsAll?.let {
            cmds.add("echo $it > /proc/sys/net/ipv4/conf/all/send_redirects 2>/dev/null; true")
        }
        snap?.sendRedirectsIface?.let {
            cmds.add("echo $it > /proc/sys/net/ipv4/conf/$iface/send_redirects 2>/dev/null; true")
        }
        snap?.ipForward?.let {
            cmds.add("echo $it > /proc/sys/net/ipv4/ip_forward 2>/dev/null; true")
        }
        if (snap?.addedDefaultRoute == true) {
            cmds.add("ip route del default via ${snap.gateway} dev ${snap.iface} 2>/dev/null; true")
        }
        return cmds
    }

    fun dnsRedirectRule(iface: String): String =
        "-t nat PREROUTING -i $iface -p udp --dport 53 -j REDIRECT --to-ports ${DnsSpoofServer.DEFAULT_PORT}"

    /** Loop a `-D` until iptables reports the rule is gone, removing every copy. */
    fun deleteAll(rule: String): String =
        "while iptables -C $rule 2>/dev/null; do iptables -D $rule 2>/dev/null || break; done; true"

    fun killCommands(targetIp: String, enable: Boolean): List<String> {
        val rules = listOf(
            "FORWARD -s $targetIp -p tcp -j REJECT --reject-with tcp-reset",
            "FORWARD -d $targetIp -p tcp -j REJECT --reject-with tcp-reset",
            "FORWARD -s $targetIp -j DROP",
            "FORWARD -d $targetIp -j DROP",
        )
        return rules.map { rule ->
            if (enable) insertIfAbsent(rule) else deleteAll(rule)
        }
    }
}
