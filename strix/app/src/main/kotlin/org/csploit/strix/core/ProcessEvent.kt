package org.csploit.strix.core

sealed class ProcessEvent {
    data class StdoutLine(val line: String) : ProcessEvent()
    data class StderrLine(val line: String) : ProcessEvent()
    data class Exited(val code: Int) : ProcessEvent()
    data class Killed(val signal: Int) : ProcessEvent()
}

/** Map a shell exit status: 129..159 means "terminated by signal (status-128)", anything else is a plain exit code. */
internal fun exitEventFor(exitValue: Int): ProcessEvent =
    if (exitValue in 129..(128 + 31)) ProcessEvent.Killed(exitValue - 128) else ProcessEvent.Exited(exitValue)
