use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

use crate::profile::DEFAULT_PROFILE_DIR;

#[derive(Debug, Parser)]
#[command(name = "runvault", version, about = "Encrypted env launcher")]
pub struct Cli {
    #[arg(global = true, short = 'p', long = "profile", value_name = "PATH")]
    pub profile: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Cmd(CmdCommand),
    #[command(name = "init", alias = "create-profile")]
    Init(CreateProfileArgs),
    Bundle(BundleArgs),
    Cache(CacheCommand),
    Encrypt(EncryptArgs),
    Jwt(JwtArgs),
    Set(SetArgs),
    Pki(PkiCommand),
    Import(ImportCommand),
    ImportFiles(ImportFilesArgs),
    Delete(DeleteArgs),
    Reveal(RevealArgs),
    Run(ProfileArgs),
    Rollback(ProfileArgs),
    Ping(PingCommand),
}

#[derive(Debug, Args)]
pub struct CmdCommand {
    #[command(subcommand)]
    pub command: CmdSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum CmdSubcommand {
    Set(CmdSetArgs),
}

#[derive(Debug, Args)]
pub struct BundleArgs {
    #[arg(value_name = "PROFILE_OR_OUTPUT", num_args = 1..=2)]
    pub targets: Vec<PathBuf>,
    #[arg(long)]
    pub version: Option<String>,
    #[arg(long)]
    pub description: Option<String>,
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct CacheCommand {
    #[command(subcommand)]
    pub command: CacheSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum CacheSubcommand {
    Clear(CacheClearArgs),
}

#[derive(Debug, Args)]
pub struct CacheClearArgs {
    pub profile: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct CreateProfileArgs {
    pub profile: Option<PathBuf>,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long = "env-file", default_value = "env.sec")]
    pub env_file: PathBuf,
}

#[derive(Debug, Args)]
pub struct EncryptArgs {
    pub input: PathBuf,
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct JwtArgs {
    #[arg(value_name = "PROFILE", num_args = 0..=1)]
    pub targets: Vec<PathBuf>,
    #[arg(long = "signing-key", value_name = "KEY")]
    pub signing_key: Option<String>,
    #[arg(long)]
    pub issuer: Option<String>,
    #[arg(long)]
    pub audience: String,
    #[arg(long)]
    pub subject: Option<String>,
    #[arg(long, default_value = "1h")]
    pub ttl: String,
    #[arg(long = "claim", value_name = "KEY=VALUE")]
    pub claims: Vec<String>,
}

#[derive(Debug, Args)]
pub struct SetArgs {
    #[arg(value_name = "PROFILE_OR_KEY", num_args = 1..=2)]
    pub targets: Vec<String>,
    #[arg(
        long,
        conflicts_with = "from_file",
        required_unless_present = "from_file"
    )]
    pub value: Option<String>,
    #[arg(
        long = "from-file",
        value_name = "PATH",
        conflicts_with = "value",
        required_unless_present = "value"
    )]
    pub from_file: Option<PathBuf>,
    #[arg(long = "to-file", alias = "value-path", value_name = "PATH")]
    pub to_file: Option<PathBuf>,
    #[arg(long, value_name = "MODE", requires = "to_file")]
    pub mode: Option<String>,
    #[arg(long, requires = "to_file", conflicts_with = "on_exit")]
    pub keep: bool,
    #[arg(long = "on-exit", requires = "to_file", conflicts_with = "keep")]
    pub on_exit: bool,
}

#[derive(Debug, Args)]
pub struct ImportCommand {
    #[command(subcommand)]
    pub command: ImportSubcommand,
}

#[derive(Debug, Args)]
pub struct PkiCommand {
    #[command(subcommand)]
    pub command: PkiSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum PkiSubcommand {
    Init(PkiInitArgs),
    Issue(PkiIssueArgs),
    Rotate(PkiRotateArgs),
}

#[derive(Debug, Args)]
pub struct PkiInitArgs {
    #[arg(long = "common-name", value_name = "NAME")]
    pub common_name: Option<String>,
    #[arg(long, default_value_t = 3650)]
    pub days: u32,
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct PkiIssueArgs {
    #[arg(long, value_name = "NAME")]
    pub name: String,
    #[arg(long = "common-name", value_name = "NAME")]
    pub common_name: Option<String>,
    #[arg(long = "dns", value_name = "NAME")]
    pub dns_names: Vec<String>,
    #[arg(long = "ip", value_name = "ADDR")]
    pub ip_addrs: Vec<String>,
    #[arg(long)]
    pub client: bool,
    #[arg(long)]
    pub server: bool,
    #[arg(long, default_value_t = 825)]
    pub days: u32,
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct PkiRotateArgs {}

#[derive(Debug, Subcommand)]
pub enum ImportSubcommand {
    Env(ImportEnvArgs),
    Resources(ImportResourcesArgs),
}

#[derive(Debug, Args)]
pub struct ImportEnvArgs {
    #[arg(value_name = "PROFILE_OR_INPUT", num_args = 1..)]
    pub targets: Vec<PathBuf>,
    #[arg(long)]
    pub prefix: Option<String>,
}

#[derive(Debug, Args)]
pub struct ImportResourcesArgs {
    #[arg(value_name = "PROFILE_OR_INPUT_OR_SRC", num_args = 0..)]
    pub targets: Vec<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub src: Option<PathBuf>,
    #[arg(long, value_name = "KEY")]
    pub key: Option<String>,
    #[arg(long = "to-file", value_name = "PATH")]
    pub to_file: Option<PathBuf>,
    #[arg(long, value_name = "MODE", requires = "to_file")]
    pub mode: Option<String>,
    #[arg(long, requires = "to_file", conflicts_with = "on_exit")]
    pub keep: bool,
    #[arg(long = "on-exit", requires = "to_file", conflicts_with = "keep")]
    pub on_exit: bool,
}

#[derive(Debug, Args)]
pub struct ImportFilesArgs {
    #[arg(value_name = "PROFILE_OR_INPUT", num_args = 1..)]
    pub targets: Vec<PathBuf>,
}

#[derive(Debug, Args)]
pub struct DeleteArgs {
    #[arg(value_name = "PROFILE_OR_KEY", num_args = 1..=2)]
    pub targets: Vec<String>,
}

#[derive(Debug, Args)]
pub struct RevealArgs {
    #[arg(value_name = "PROFILE_OR_KEY", num_args = 1..=2)]
    pub targets: Vec<String>,
    #[arg(long)]
    pub raw: bool,
    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ProfileArgs {
    pub profile: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct CmdSetArgs {
    #[arg(trailing_var_arg = true, required = true)]
    pub parts: Vec<String>,
}

#[derive(Debug, Args)]
pub struct PingCommand {
    #[command(subcommand)]
    pub command: Option<PingSubcommand>,
    pub profile: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum PingSubcommand {
    Add(PingAddArgs),
}

#[derive(Debug, Args)]
pub struct PingAddArgs {
    #[arg(value_name = "PROFILE_OR_NAME_OR_URL", num_args = 2..=3)]
    pub targets: Vec<String>,
    #[arg(long, default_value_t = 30)]
    pub timeout_seconds: u64,
    #[arg(long, default_value_t = 500)]
    pub interval_millis: u64,
}

impl CacheClearArgs {
    pub fn profile_or_default(&self, global_profile: Option<&PathBuf>) -> PathBuf {
        global_profile
            .cloned()
            .or_else(|| self.profile.clone())
            .unwrap_or_else(|| PathBuf::from(DEFAULT_PROFILE_DIR))
    }
}

impl CreateProfileArgs {
    pub fn profile_or_default(&self, global_profile: Option<&PathBuf>) -> PathBuf {
        global_profile
            .cloned()
            .or_else(|| self.profile.clone())
            .unwrap_or_else(|| PathBuf::from(DEFAULT_PROFILE_DIR))
    }
}

impl BundleArgs {
    pub fn resolve(&self, global_profile: Option<&PathBuf>) -> (PathBuf, PathBuf) {
        match self.targets.as_slice() {
            [output] if global_profile.is_some() => {
                (global_profile.cloned().unwrap(), output.clone())
            }
            [output] => (PathBuf::from(DEFAULT_PROFILE_DIR), output.clone()),
            [profile, output] => (
                global_profile.cloned().unwrap_or_else(|| profile.clone()),
                output.clone(),
            ),
            _ => unreachable!("clap enforces bundle target arity"),
        }
    }
}

impl SetArgs {
    pub fn resolve(&self, global_profile: Option<&PathBuf>) -> (PathBuf, String) {
        match self.targets.as_slice() {
            [key] => (
                global_profile
                    .cloned()
                    .unwrap_or_else(|| PathBuf::from(DEFAULT_PROFILE_DIR)),
                key.clone(),
            ),
            [profile, key] => (
                global_profile
                    .cloned()
                    .unwrap_or_else(|| PathBuf::from(profile)),
                key.clone(),
            ),
            _ => unreachable!("clap enforces set target arity"),
        }
    }
}

impl JwtArgs {
    pub fn resolve(&self, global_profile: Option<&PathBuf>) -> PathBuf {
        match self.targets.as_slice() {
            [] => global_profile
                .cloned()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_PROFILE_DIR)),
            [profile] => global_profile.cloned().unwrap_or_else(|| profile.clone()),
            _ => unreachable!("clap enforces jwt target arity"),
        }
    }
}

impl ImportEnvArgs {
    pub fn resolve(&self, global_profile: Option<&PathBuf>) -> (PathBuf, Vec<PathBuf>) {
        if let Some(profile) = global_profile {
            return (profile.clone(), self.targets.clone());
        }
        match self.targets.as_slice() {
            [input] => (PathBuf::from(DEFAULT_PROFILE_DIR), vec![input.clone()]),
            [first, rest @ ..] if looks_like_profile_path(first) => (first.clone(), rest.to_vec()),
            inputs => (PathBuf::from(DEFAULT_PROFILE_DIR), inputs.to_vec()),
        }
    }
}

impl ImportResourcesArgs {
    pub fn resolve(&self, global_profile: Option<&PathBuf>) -> (PathBuf, Vec<PathBuf>) {
        if let Some(profile) = global_profile {
            return (profile.clone(), self.targets.clone());
        }
        match self.targets.as_slice() {
            [input] => (PathBuf::from(DEFAULT_PROFILE_DIR), vec![input.clone()]),
            [first, rest @ ..] if looks_like_profile_path(first) => (first.clone(), rest.to_vec()),
            inputs => (PathBuf::from(DEFAULT_PROFILE_DIR), inputs.to_vec()),
        }
    }

    pub fn uses_inline_spec(&self) -> bool {
        self.src.is_some()
            || self.to_file.is_some()
            || self.mode.is_some()
            || self.keep
            || self.on_exit
    }

    pub fn resolve_inline(
        &self,
        global_profile: Option<&PathBuf>,
    ) -> Result<(PathBuf, PathBuf), String> {
        if self.to_file.is_none() {
            return Err("--to-file is required when importing a single resource".to_string());
        }

        if let Some(src) = &self.src {
            return match global_profile {
                Some(profile) => {
                    if self.targets.is_empty() {
                        Ok((profile.clone(), src.clone()))
                    } else {
                        Err(
                            "single resource import expects no positional arguments when -p/--profile and --src are both used"
                                .to_string(),
                        )
                    }
                }
                None => match self.targets.as_slice() {
                    [] => Ok((PathBuf::from(DEFAULT_PROFILE_DIR), src.clone())),
                    [profile] if looks_like_profile_path(profile) => Ok((profile.clone(), src.clone())),
                    _ => Err(
                        "single resource import expects only an optional PROFILE when --src is used"
                            .to_string(),
                    ),
                },
            };
        }

        if let Some(profile) = global_profile {
            return match self.targets.as_slice() {
                [src] => Ok((profile.clone(), src.clone())),
                _ => Err(
                    "single resource import expects exactly one positional source path when -p/--profile is used"
                        .to_string(),
                ),
            };
        }

        match self.targets.as_slice() {
            [src] => Ok((PathBuf::from(DEFAULT_PROFILE_DIR), src.clone())),
            [profile, src] if looks_like_profile_path(profile) => {
                Ok((profile.clone(), src.clone()))
            }
            _ => Err(
                "single resource import expects SOURCE_PATH plus optional PROFILE before it"
                    .to_string(),
            ),
        }
    }
}

impl ImportFilesArgs {
    pub fn resolve(&self, global_profile: Option<&PathBuf>) -> (PathBuf, Vec<PathBuf>) {
        if let Some(profile) = global_profile {
            return (profile.clone(), self.targets.clone());
        }
        match self.targets.as_slice() {
            [input] => (PathBuf::from(DEFAULT_PROFILE_DIR), vec![input.clone()]),
            [first, rest @ ..] if looks_like_profile_path(first) => (first.clone(), rest.to_vec()),
            inputs => (PathBuf::from(DEFAULT_PROFILE_DIR), inputs.to_vec()),
        }
    }
}

impl DeleteArgs {
    pub fn resolve(&self, global_profile: Option<&PathBuf>) -> (PathBuf, String) {
        match self.targets.as_slice() {
            [key] => (
                global_profile
                    .cloned()
                    .unwrap_or_else(|| PathBuf::from(DEFAULT_PROFILE_DIR)),
                key.clone(),
            ),
            [profile, key] => (
                global_profile
                    .cloned()
                    .unwrap_or_else(|| PathBuf::from(profile)),
                key.clone(),
            ),
            _ => unreachable!("clap enforces delete target arity"),
        }
    }
}

impl RevealArgs {
    pub fn resolve(&self, global_profile: Option<&PathBuf>) -> (PathBuf, String) {
        match self.targets.as_slice() {
            [key] => (
                global_profile
                    .cloned()
                    .unwrap_or_else(|| PathBuf::from(DEFAULT_PROFILE_DIR)),
                key.clone(),
            ),
            [profile, key] => (
                global_profile
                    .cloned()
                    .unwrap_or_else(|| PathBuf::from(profile)),
                key.clone(),
            ),
            _ => unreachable!("clap enforces reveal target arity"),
        }
    }
}

impl ProfileArgs {
    pub fn profile_or_default(&self, global_profile: Option<&PathBuf>) -> PathBuf {
        global_profile
            .cloned()
            .or_else(|| self.profile.clone())
            .unwrap_or_else(|| PathBuf::from(DEFAULT_PROFILE_DIR))
    }

    pub fn explicit_profile(&self, global_profile: Option<&PathBuf>) -> Option<PathBuf> {
        global_profile.cloned().or_else(|| self.profile.clone())
    }
}

impl CmdSetArgs {
    pub fn resolve(&self, global_profile: Option<&PathBuf>) -> (PathBuf, Vec<String>) {
        match self.parts.as_slice() {
            [cmd @ ..] if !cmd.is_empty() => {
                let first = PathBuf::from(&cmd[0]);
                let (profile, mut command) = if let Some(profile) = global_profile {
                    (profile.clone(), cmd.to_vec())
                } else if cmd.len() >= 2 && looks_like_profile_path(&first) {
                    (first, cmd[1..].to_vec())
                } else {
                    (PathBuf::from(DEFAULT_PROFILE_DIR), cmd.to_vec())
                };
                if command.first().is_some_and(|value| value == "--") {
                    command.remove(0);
                }
                (profile, command)
            }
            _ => unreachable!("clap enforces run set arity"),
        }
    }
}

impl PingCommand {
    pub fn profile_or_default(&self, global_profile: Option<&PathBuf>) -> PathBuf {
        global_profile
            .cloned()
            .or_else(|| self.profile.clone())
            .unwrap_or_else(|| PathBuf::from(DEFAULT_PROFILE_DIR))
    }
}

impl PingAddArgs {
    pub fn resolve(&self, global_profile: Option<&PathBuf>) -> (PathBuf, String, String) {
        match self.targets.as_slice() {
            [name, url] => (
                global_profile
                    .cloned()
                    .unwrap_or_else(|| PathBuf::from(DEFAULT_PROFILE_DIR)),
                name.clone(),
                url.clone(),
            ),
            [profile, name, url] => (
                global_profile
                    .cloned()
                    .unwrap_or_else(|| PathBuf::from(profile)),
                name.clone(),
                url.clone(),
            ),
            _ => unreachable!("clap enforces ping add target arity"),
        }
    }
}

fn looks_like_profile_path(path: &PathBuf) -> bool {
    if path.file_name().is_some_and(|name| name == "runvault.yaml") {
        return true;
    }

    path.join("runvault.yaml").exists()
}

#[cfg(test)]
mod tests {
    use super::{
        Cli, CmdSubcommand, Command, DEFAULT_PROFILE_DIR, ImportSubcommand, PingSubcommand,
        PkiSubcommand,
    };
    use clap::Parser;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn import_defaults_to_dot_vault_for_multiple_inputs() {
        let cli = Cli::try_parse_from(["runvault", "import", "env", ".env", ".env.local"]).unwrap();

        let Command::Import(args) = cli.command else {
            panic!("expected import command");
        };
        let ImportSubcommand::Env(args) = args.command else {
            panic!("expected import env subcommand");
        };

        let (profile, inputs) = args.resolve(None);
        assert_eq!(profile, PathBuf::from(DEFAULT_PROFILE_DIR));
        assert_eq!(
            inputs,
            vec![PathBuf::from(".env"), PathBuf::from(".env.local")]
        );
    }

    #[test]
    fn jwt_defaults_to_dot_vault_for_profile() {
        let cli = Cli::try_parse_from(["runvault", "jwt", "--audience", "tempo"]).unwrap();

        let Command::Jwt(args) = cli.command else {
            panic!("expected jwt command");
        };

        let profile = args.resolve(None);
        assert_eq!(profile, PathBuf::from(DEFAULT_PROFILE_DIR));
        assert_eq!(args.audience, "tempo");
    }

    #[test]
    fn jwt_accepts_explicit_profile() {
        let cli = Cli::try_parse_from([
            "runvault",
            "jwt",
            "deployments/ovh/services",
            "--audience",
            "tempo",
        ])
        .unwrap();

        let Command::Jwt(args) = cli.command else {
            panic!("expected jwt command");
        };

        let profile = args.resolve(None);
        assert_eq!(profile, PathBuf::from("deployments/ovh/services"));
    }

    #[test]
    fn ping_add_defaults_to_dot_vault_for_name_and_url() {
        let cli = Cli::try_parse_from([
            "runvault",
            "ping",
            "add",
            "api",
            "http://127.0.0.1:8080/health",
        ])
        .unwrap();

        let Command::Ping(args) = cli.command else {
            panic!("expected ping command");
        };
        let Some(PingSubcommand::Add(add)) = args.command else {
            panic!("expected ping add subcommand");
        };

        let (profile, name, url) = add.resolve(None);
        assert_eq!(profile, PathBuf::from(DEFAULT_PROFILE_DIR));
        assert_eq!(name, "api");
        assert_eq!(url, "http://127.0.0.1:8080/health");
        assert_eq!(add.timeout_seconds, 30);
        assert_eq!(add.interval_millis, 500);
    }

    #[test]
    fn cmd_set_defaults_to_dot_vault_and_collects_command_after_separator() {
        let cli = Cli::try_parse_from([
            "runvault", "cmd", "set", "--", "docker", "compose", "up", "-d",
        ])
        .unwrap();

        let Command::Cmd(args) = cli.command else {
            panic!("expected cmd command");
        };
        let CmdSubcommand::Set(set) = args.command;
        let (profile, cmd) = set.resolve(None);
        assert_eq!(profile, PathBuf::from(DEFAULT_PROFILE_DIR));
        assert_eq!(cmd, vec!["docker", "compose", "up", "-d"]);
    }

    #[test]
    fn cmd_set_uses_explicit_profile_before_separator_when_profile_exists() {
        let profile_dir = unique_temp_dir("runvault-cli-cmd-set-profile");
        fs::create_dir_all(&profile_dir).unwrap();
        fs::write(
            profile_dir.join("runvault.yaml"),
            "name: test\nrun:\n  cmd: [\"true\"]\n",
        )
        .unwrap();

        let cli = Cli::try_parse_from([
            "runvault",
            "cmd",
            "set",
            profile_dir.to_str().unwrap(),
            "--",
            "docker",
            "compose",
            "up",
            "-d",
        ])
        .unwrap();

        let Command::Cmd(args) = cli.command else {
            panic!("expected cmd command");
        };
        let CmdSubcommand::Set(set) = args.command;

        let (profile, cmd) = set.resolve(None);
        assert_eq!(profile, profile_dir);
        assert_eq!(cmd, vec!["docker", "compose", "up", "-d"]);
    }

    #[test]
    fn global_profile_flag_applies_to_import_env_without_profile_path_heuristics() {
        let cli = Cli::try_parse_from([
            "runvault",
            "--profile",
            "deployments/ovh/services",
            "import",
            "env",
            ".env",
            ".env.local",
        ])
        .unwrap();

        let global_profile = cli.profile.as_ref();
        let Command::Import(args) = cli.command else {
            panic!("expected import command");
        };
        let ImportSubcommand::Env(args) = args.command else {
            panic!("expected import env subcommand");
        };

        let (profile, inputs) = args.resolve(global_profile);
        assert_eq!(profile, PathBuf::from("deployments/ovh/services"));
        assert_eq!(
            inputs,
            vec![PathBuf::from(".env"), PathBuf::from(".env.local")]
        );
    }

    #[test]
    fn global_profile_flag_overrides_legacy_positional_profile_for_set() {
        let cli = Cli::try_parse_from([
            "runvault",
            "--profile",
            "deployments/ovh/services",
            "set",
            "ignored-profile",
            "DATABASE_URL",
            "--value",
            "postgres://db",
        ])
        .unwrap();

        let global_profile = cli.profile.as_ref();
        let Command::Set(args) = cli.command else {
            panic!("expected set command");
        };

        let (profile, key) = args.resolve(global_profile);
        assert_eq!(profile, PathBuf::from("deployments/ovh/services"));
        assert_eq!(key, "DATABASE_URL");
    }

    #[test]
    fn pki_init_accepts_global_profile_flag() {
        let cli = Cli::try_parse_from([
            "runvault",
            "--profile",
            "deployments/ovh/services",
            "pki",
            "init",
            "--days",
            "3650",
            "--force",
        ])
        .unwrap();

        assert_eq!(cli.profile, Some(PathBuf::from("deployments/ovh/services")));
        let Command::Pki(args) = cli.command else {
            panic!("expected pki command");
        };
        let PkiSubcommand::Init(args) = args.command else {
            panic!("expected pki init subcommand");
        };
        assert_eq!(args.days, 3650);
        assert!(args.force);
    }

    #[test]
    fn pki_issue_parses_dns_and_ip_options() {
        let cli = Cli::try_parse_from([
            "runvault",
            "pki",
            "issue",
            "--name",
            "api.service.local",
            "--dns",
            "api.service.local",
            "--ip",
            "127.0.0.1",
            "--server",
            "--force",
        ])
        .unwrap();

        let Command::Pki(args) = cli.command else {
            panic!("expected pki command");
        };
        let PkiSubcommand::Issue(args) = args.command else {
            panic!("expected pki issue subcommand");
        };
        assert_eq!(args.name, "api.service.local");
        assert_eq!(args.dns_names, vec!["api.service.local"]);
        assert_eq!(args.ip_addrs, vec!["127.0.0.1"]);
        assert!(args.server);
        assert!(!args.client);
        assert!(args.force);
    }

    #[test]
    fn pki_rotate_parses_without_profile() {
        let cli = Cli::try_parse_from(["runvault", "pki", "rotate"]).unwrap();

        let Command::Pki(args) = cli.command else {
            panic!("expected pki command");
        };
        let PkiSubcommand::Rotate(_args) = args.command else {
            panic!("expected pki rotate subcommand");
        };
    }

    #[test]
    fn bundle_export_defaults_to_dot_vault_for_output_path() {
        let cli = Cli::try_parse_from(["runvault", "bundle", "profile.bundle.yaml"]).unwrap();

        let Command::Bundle(args) = cli.command else {
            panic!("expected bundle command");
        };

        let (profile, output) = args.resolve(None);
        assert_eq!(profile, PathBuf::from(DEFAULT_PROFILE_DIR));
        assert_eq!(output, PathBuf::from("profile.bundle.yaml"));
        assert!(!args.force);
    }

    #[test]
    fn bundle_export_accepts_force_flag() {
        let cli =
            Cli::try_parse_from(["runvault", "bundle", "profile.bundle.yaml", "--force"]).unwrap();

        let Command::Bundle(args) = cli.command else {
            panic!("expected bundle command");
        };

        assert!(args.force);
    }

    #[test]
    fn import_uses_explicit_profile_when_runvault_yaml_exists() {
        let profile_dir = unique_temp_dir("runvault-cli-import-profile");
        fs::create_dir_all(&profile_dir).unwrap();
        fs::write(
            profile_dir.join("runvault.yaml"),
            "name: test\nrun:\n  cmd: [\"true\"]\n",
        )
        .unwrap();

        let cli = Cli::try_parse_from([
            "runvault",
            "import",
            "env",
            profile_dir.to_str().unwrap(),
            ".env",
            ".env.local",
        ])
        .unwrap();

        let Command::Import(args) = cli.command else {
            panic!("expected import command");
        };
        let ImportSubcommand::Env(args) = args.command else {
            panic!("expected import env subcommand");
        };

        let (profile, inputs) = args.resolve(None);
        assert_eq!(profile, profile_dir);
        assert_eq!(
            inputs,
            vec![PathBuf::from(".env"), PathBuf::from(".env.local")]
        );
    }

    #[test]
    fn import_resources_defaults_to_dot_vault_for_multiple_specs() {
        let cli = Cli::try_parse_from([
            "runvault",
            "import",
            "resources",
            "resources-a.yaml",
            "resources-b.yaml",
        ])
        .unwrap();

        let Command::Import(args) = cli.command else {
            panic!("expected import command");
        };
        let ImportSubcommand::Resources(args) = args.command else {
            panic!("expected import resources subcommand");
        };

        let (profile, inputs) = args.resolve(None);
        assert_eq!(profile, PathBuf::from(DEFAULT_PROFILE_DIR));
        assert_eq!(
            inputs,
            vec![
                PathBuf::from("resources-a.yaml"),
                PathBuf::from("resources-b.yaml")
            ]
        );
    }

    #[test]
    fn import_resources_accepts_direct_single_resource_form() {
        let cli = Cli::try_parse_from([
            "runvault",
            "import",
            "resources",
            "docker-compose.yml",
            "--to-file",
            "./docker-compose.yml",
            "--mode",
            "0644",
        ])
        .unwrap();

        let Command::Import(args) = cli.command else {
            panic!("expected import command");
        };
        let ImportSubcommand::Resources(args) = args.command else {
            panic!("expected import resources subcommand");
        };

        assert!(args.uses_inline_spec());
        let (profile, src) = args.resolve_inline(None).unwrap();
        assert_eq!(profile, PathBuf::from(DEFAULT_PROFILE_DIR));
        assert_eq!(src, PathBuf::from("docker-compose.yml"));
        assert_eq!(args.to_file, Some(PathBuf::from("./docker-compose.yml")));
        assert_eq!(args.mode.as_deref(), Some("0644"));
    }

    #[test]
    fn import_resources_accepts_direct_form_with_explicit_profile_flag() {
        let cli = Cli::try_parse_from([
            "runvault",
            "--profile",
            "deployments/home/workers",
            "import",
            "resources",
            "docker-compose.yml",
            "--to-file",
            "./docker-compose.yml",
        ])
        .unwrap();

        let global_profile = cli.profile.as_ref();
        let Command::Import(args) = cli.command else {
            panic!("expected import command");
        };
        let ImportSubcommand::Resources(args) = args.command else {
            panic!("expected import resources subcommand");
        };

        let (profile, src) = args.resolve_inline(global_profile).unwrap();
        assert_eq!(profile, PathBuf::from("deployments/home/workers"));
        assert_eq!(src, PathBuf::from("docker-compose.yml"));
    }

    #[test]
    fn import_files_defaults_to_dot_vault_for_multiple_specs() {
        let cli = Cli::try_parse_from(["runvault", "import-files", "files-a.yaml", "files-b.yaml"])
            .unwrap();

        let Command::ImportFiles(args) = cli.command else {
            panic!("expected import-files command");
        };

        let (profile, inputs) = args.resolve(None);
        assert_eq!(profile, PathBuf::from(DEFAULT_PROFILE_DIR));
        assert_eq!(
            inputs,
            vec![PathBuf::from("files-a.yaml"), PathBuf::from("files-b.yaml")]
        );
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("{prefix}-{nanos}"));
        path
    }
}
