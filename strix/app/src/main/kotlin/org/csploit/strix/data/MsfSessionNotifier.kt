package org.csploit.strix.data

import org.csploit.strix.core.Logger
import org.csploit.strix.core.StrixNotifications

/**
 * One session.list poll: post a notification for each new session id, then
 * drop ids that have closed so a reused id re-notifies.
 */
internal suspend fun notifyNewSessions(
    rpcClient: MsfRpcClient,
    notifications: StrixNotifications,
    seenSessionIds: MutableSet<Int>,
) {
    val sessions = rpcClient.sessionList()
    for (s in sessions) {
        if (seenSessionIds.add(s.id)) {
            val info = buildString {
                append(s.type)
                if (s.targetHost.isNotEmpty()) append(" @ ${s.targetHost}")
                if (s.viaExploit.isNotEmpty()) append(" via ${s.viaExploit}")
            }
            notifications.notifySessionOpened(s.id, info)
            Logger.info("MsfDaemon: session opened #${s.id} $info")
        }
    }
    // Drop ids that have closed so we re-notify if an id is reused.
    val currentIds = sessions.map { it.id }.toSet()
    seenSessionIds.retainAll(currentIds)
}
