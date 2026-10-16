import ghidra.app.script.GhidraScript;

public class RuntimeProbe extends GhidraScript {
    public void run() {
        println(RuntimeHelper.message() + ":" + currentProgram.getName() + ":" + getScriptArgs()[0]);
        printerr("RUNTIME_STDERR");
    }
}
