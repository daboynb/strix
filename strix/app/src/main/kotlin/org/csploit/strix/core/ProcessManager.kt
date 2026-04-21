package org.csploit.strix.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import javax.inject.Inject
import javax.inject.Singleton

sealed class ProcessEvent {
    data class StdoutLine(val line: String) : ProcessEvent()
    data class StderrLine(val line: String) : ProcessEvent()
    data class Exited(val code: Int) : ProcessEvent()
    data class Killed(val signal: Int) : ProcessEvent()
}

@Singleton
class ProcessManager @Inject constructor() {

    /**
     * Execute a command via su and emit output as a Flow.
     * The process is killed when the Flow collector is cancelled.
     */
    fun execute(
        command: String,
        env: Map<String, String> = emptyMap(),
        toolsDir: String? = null,
        workDir: String? = null,
        asSu: Boolean = true,
    ): Flow<ProcessEvent> = callbackFlow {
        val shellCmd = buildShellCommand(command, env, toolsDir, workDir)

        val pb = if (asSu) {
            ProcessBuilder("su", "-c", shellCmd)
        } else {
            ProcessBuilder("sh", "-c", shellCmd)
        }
        pb.redirectErrorStream(false)

        val process = withContext(Dispatchers.IO) { pb.start() }

        Logger.debug("ProcessManager: started cmd=$command")

        val stdoutJob = launch(Dispatchers.IO) {
            try {
                BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                    var line = reader.readLine()
                    while (line != null) {
                        trySend(ProcessEvent.StdoutLine(line))
                        line = reader.readLine()
                    }
                }
            } catch (_: java.io.IOException) {
                // Stream closed or interrupted during cancellation
            }
        }

        val stderrJob = launch(Dispatchers.IO) {
            try {
                BufferedReader(InputStreamReader(process.errorStream)).use { reader ->
                    var line = reader.readLine()
                    while (line != null) {
                        trySend(ProcessEvent.StderrLine(line))
                        line = reader.readLine()
                    }
                }
            } catch (_: java.io.IOException) {
                // Stream closed or interrupted during cancellation
            }
        }

        launch(Dispatchers.IO) {
            stdoutJob.join()
            stderrJob.join()
            val exitValue = process.waitFor()
            if (exitValue > 128) {
                trySend(ProcessEvent.Killed(exitValue - 128))
            } else {
                trySend(ProcessEvent.Exited(exitValue))
            }
            close()
        }

        awaitClose {
            Logger.debug("ProcessManager: killing process for cmd=$command")
            process.destroyForcibly()
        }
    }

    private fun buildShellCommand(
        command: String,
        env: Map<String, String>,
        toolsDir: String?,
        workDir: String?,
    ): String = buildString {
        if (workDir != null) {
            append("cd '").append(workDir).append("' ; ")
        }
        if (toolsDir != null) {
            val dir = toolsDir.trimEnd('/')
            val dollar = '$'
            append("export PATH=").append(dir).append("/bin:").append(dollar).append("PATH ; ")
            append("export NMAPDIR=").append(dir).append("/share/nmap ; ")
        }
        for ((key, value) in env) {
            append("export ").append(key).append("='").append(value).append("' ; ")
        }
        append(command)
    }
}
