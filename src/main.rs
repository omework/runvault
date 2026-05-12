use runvault::Runvault;

#[tokio::main]
async fn main() {
    if let Err(err) = Runvault::default().run_cli_env().await {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}
