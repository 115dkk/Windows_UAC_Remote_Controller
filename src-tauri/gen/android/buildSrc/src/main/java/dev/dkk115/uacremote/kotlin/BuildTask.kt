import java.io.File
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.logging.LogLevel
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.TaskAction

open class BuildTask : DefaultTask() {
    @Input
    var rootDirRel: String? = null
    @Input
    var target: String? = null
    @Input
    var release: Boolean? = null

    @TaskAction
    fun assemble() {
        // Build-time tool selection, not renderer input. Never retry an
        // already-started failed build or embed one developer's machine path.
        runTauriCli(System.getenv("NODE_BINARY")?.takeIf { it.isNotBlank() } ?: "node")
    }

    fun runTauriCli(executable: String) {
        val rootDirRel = rootDirRel ?: throw GradleException("rootDirRel cannot be null")
        val target = target ?: throw GradleException("target cannot be null")
        val release = release ?: throw GradleException("release cannot be null")
        val root = File(project.projectDir, rootDirRel).canonicalFile
        val cli = File(root.parentFile, "node_modules/@tauri-apps/cli/tauri.js")
        if (!cli.isFile) throw GradleException("Install the locked Tauri CLI before building Android")
        val args = listOf(cli.absolutePath, "android", "android-studio-script")

        project.exec {
            workingDir(root)
            executable(executable)
            args(args)
            if (project.logger.isEnabled(LogLevel.DEBUG)) {
                args("-vv")
            } else if (project.logger.isEnabled(LogLevel.INFO)) {
                args("-v")
            }
            if (release) {
                args("--release")
            }
            args(listOf("--target", target))
        }.assertNormalExitValue()
    }
}
