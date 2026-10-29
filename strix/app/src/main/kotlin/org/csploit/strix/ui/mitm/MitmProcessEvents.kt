package org.csploit.strix.ui.mitm

import org.csploit.strix.core.ProcessEvent

/** Map an arpspoof process event to log lines; [onDied] fires on an unexpected exit. */
internal fun handleArpSpoofEvent(
    event: ProcessEvent,
    log: (String) -> Unit,
    onDied: () -> Unit,
) {
    when (event) {
        is ProcessEvent.StdoutLine -> {} // suppress arp reply noise
        is ProcessEvent.StderrLine -> {
            if (event.line.contains("couldn't") || event.line.contains("error"))
                log("[arpspoof] ${event.line}")
        }
        is ProcessEvent.Exited -> {
            log("[arpspoof exited: ${event.code}]")
            onDied()
        }
        is ProcessEvent.Killed -> log("[arpspoof stopped]")
    }
}

/**
 * Map a tcpdump credential-sniffer event: stdout goes to [onTraffic] for
 * credential parsing and to the log; [onDied] fires on an unexpected exit.
 */
internal fun handleSnifferEvent(
    event: ProcessEvent,
    log: (String) -> Unit,
    onTraffic: (String) -> Unit,
    onDied: () -> Unit,
) {
    when (event) {
        is ProcessEvent.StdoutLine -> {
            onTraffic(event.line)
            val trimmed = event.line.trim()
            if (trimmed.isNotEmpty() && !trimmed.startsWith("E.")) {
                log("[tcp] ${trimmed.take(100)}")
            }
        }
        is ProcessEvent.StderrLine -> {
            if (event.line.contains("listening on") || event.line.contains("packets")) {
                log("[sniffer] ${event.line}")
            }
        }
        is ProcessEvent.Exited -> {
            log("[sniffer exited: ${event.code}]")
            onDied()
        }
        is ProcessEvent.Killed -> log("[sniffer killed]")
    }
}
