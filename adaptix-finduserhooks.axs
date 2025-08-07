var metadata = {
    name: "Hooks",
    description: "BOF used for finding hooked functions and syscalls"
};

var cmd_hooks = ax.create_command("hooks", "Detect userland hooks in all loaded modules", "hooks");
cmd_hooks.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "bin/finduserhooks." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "Detecting userland hooks");
});

var group_test = ax.create_commands_group("Hooks-BOF", [cmd_hooks]);
ax.register_commands_group(group_test, ["beacon", "gopher"], ["windows"], []);