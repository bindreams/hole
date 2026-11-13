# Command line

The app is the main way to use Hole. These commands are for scripting and recovery; `hole --help` lists the
subcommands meant for people.

| Command                              | Description                                                                                                        |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| `hole [--no-show-dashboard]`         | Launch the app. It opens the dashboard unless `--no-show-dashboard` starts it in the tray only.                    |
| `hole version`                       | Print version information.                                                                                         |
| `hole upgrade [-y]`                  | Check for updates and install the latest version. `-y` answers yes to the consent prompt, for non-interactive use. |
| `hole path add` / `hole path remove` | Add or remove `hole` from the system `PATH`. Run it as administrator (`sudo` on macOS).                            |
| `hole bridge unlock`                 | Turn the {term}`kill switch` off and clear the block it left behind. Run it as administrator (`sudo` on macOS).    |

`hole bridge unlock` is the recovery route when no bridge is running. While one is, it refuses: use the app's **Unblock
Network** action instead.

The remaining `hole bridge` and `hole proxy` subcommands are for development and administration. They are listed in
the {src}`dev/admin CLI section of CONTRIBUTING.md <CONTRIBUTING.md#cli-devadmin-commands>`.
